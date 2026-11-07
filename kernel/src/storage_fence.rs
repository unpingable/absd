//! Whether this boot's block device is fenced against the effects of an
//! earlier generation's commands (docs/STORAGE-STALE-WRITE-FENCE.md).
//!
//! A machine reset retires nothing by itself. A backend that reported a
//! write failed, or held it across the reset, may still apply it later; F3's
//! ghost-write case shows the bytes landing in the active image after the
//! successor was serving. No software check on this side of the controller
//! can exclude that, so the owner's rule (2026-10-17, decision (b)) is: a
//! successor whose predecessor did not end cleanly is refused writable
//! recovery unless a fence is established. This module only classifies;
//! the file server applies the rule, because only its recovery ledger
//! knows how the predecessor ended.
//!
//! A declaration is an input to assessment, not evidence of retirement.
//! NVMe's disable handshake establishes a controller transition; it does
//! not establish the backing service's command retirement. In particular,
//! an NVMe presentation may be backed by NBD with a retained write. PCI
//! identity and the `controller` word cannot distinguish that case.
//! No driver (ATA, NVMe, AHCI) currently supplies a checked end-to-end fence, and
//! `external` has no checked completion record. All these cases therefore
//! remain not established. A future positive path needs its own mechanism,
//! correspondence and qualification; adding another boot word is not one.

/// The operator's `storage-fence=` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Declaration {
    None,
    Controller,
    External,
    /// A value this kernel does not know: never a fence.
    Invalid,
}

impl Declaration {
    pub fn parse(value: Option<&[u8]>) -> Self {
        match value {
            None => Self::None,
            Some(b"controller") => Self::Controller,
            Some(b"external") => Self::External,
            Some(_) => Self::Invalid,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Ata,
    Nvme,
    /// AHCI port stop and restart only: no COMRESET, no HBA reset.
    Ahci,
}

/// The classification, with the word the console line and the file server
/// print.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fence {
    /// No fence: a successor of an unclean end must not write.
    NotEstablished(Reason),
}

/// Why no fence is established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// No `storage-fence=` option.
    NotDeclared,
    /// `storage-fence=` named a value this kernel does not know.
    InvalidDeclaration,
    /// `controller` on a backend whose driver performs no reset.
    NoControllerReset,
    /// Controller state says nothing about a retained backing-service command.
    BackendUnverified,
    /// No checked external retirement mechanism was supplied.
    ExternalUnverified,
    /// The device is read-only this boot: there is nothing to fence.
    ReadOnly,
}

impl Reason {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotDeclared => "not_declared",
            Self::InvalidDeclaration => "invalid_declaration",
            Self::NoControllerReset => "no_controller_reset",
            Self::BackendUnverified => "backend_unverified",
            Self::ExternalUnverified => "external_unverified",
            Self::ReadOnly => "read_only",
        }
    }
}

impl Fence {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotEstablished(_) => "none",
        }
    }

    /// The two-bit word init receives (`program::init_with_fence`).
    pub const fn word(self) -> u64 {
        match self {
            Self::NotEstablished(_) => crate::program::INIT_FENCE_NONE,
        }
    }
}

/// `controller_disabled`: the NVMe probe observed CSTS.RDY=0 with CC.EN=0
/// before rebuilding its queues (always true of a probe that succeeded;
/// carried so the rule does not depend on that).
pub fn classify(
    backend: Backend,
    writable: bool,
    declaration: Declaration,
    controller_disabled: bool,
) -> Fence {
    if !writable {
        return Fence::NotEstablished(Reason::ReadOnly);
    }
    match declaration {
        Declaration::None => Fence::NotEstablished(Reason::NotDeclared),
        Declaration::Invalid => Fence::NotEstablished(Reason::InvalidDeclaration),
        Declaration::External => Fence::NotEstablished(Reason::ExternalUnverified),
        Declaration::Controller => match backend {
            Backend::Nvme if controller_disabled => {
                Fence::NotEstablished(Reason::BackendUnverified)
            }
            Backend::Nvme | Backend::Ata | Backend::Ahci => {
                Fence::NotEstablished(Reason::NoControllerReset)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_parse_exactly() {
        assert_eq!(Declaration::parse(None), Declaration::None);
        assert_eq!(
            Declaration::parse(Some(b"controller")),
            Declaration::Controller
        );
        assert_eq!(Declaration::parse(Some(b"external")), Declaration::External);
        for other in [&b""[..], b"Controller", b"controller ", b"reset", b"none"] {
            assert_eq!(
                Declaration::parse(Some(other)),
                Declaration::Invalid,
                "{other:?}"
            );
        }
    }

    #[test]
    fn declarations_never_establish_an_external_fence() {
        for backend in [Backend::Ata, Backend::Nvme, Backend::Ahci] {
            assert_eq!(
                classify(backend, true, Declaration::None, true),
                Fence::NotEstablished(Reason::NotDeclared)
            );
            assert_eq!(
                classify(backend, true, Declaration::Invalid, true),
                Fence::NotEstablished(Reason::InvalidDeclaration)
            );
            assert_eq!(
                classify(backend, true, Declaration::External, false),
                Fence::NotEstablished(Reason::ExternalUnverified)
            );
        }
    }

    #[test]
    fn nvme_disable_does_not_establish_backing_command_retirement() {
        assert_eq!(
            classify(Backend::Nvme, true, Declaration::Controller, true),
            Fence::NotEstablished(Reason::BackendUnverified)
        );
        assert_eq!(
            classify(Backend::Nvme, true, Declaration::Controller, false),
            Fence::NotEstablished(Reason::NoControllerReset)
        );
        assert_eq!(
            classify(Backend::Ata, true, Declaration::Controller, true),
            Fence::NotEstablished(Reason::NoControllerReset)
        );
        assert_eq!(
            classify(Backend::Ahci, true, Declaration::Controller, false),
            Fence::NotEstablished(Reason::NoControllerReset)
        );
    }

    #[test]
    fn a_read_only_device_has_nothing_to_fence() {
        for declaration in [
            Declaration::None,
            Declaration::Controller,
            Declaration::External,
        ] {
            assert_eq!(
                classify(Backend::Nvme, false, declaration, true),
                Fence::NotEstablished(Reason::ReadOnly)
            );
        }
    }

    #[test]
    fn every_current_backend_and_declaration_forwards_no_fence() {
        for backend in [Backend::Ata, Backend::Nvme, Backend::Ahci] {
            for declaration in [
                Declaration::None,
                Declaration::Controller,
                Declaration::External,
                Declaration::Invalid,
            ] {
                for writable in [false, true] {
                    for disabled in [false, true] {
                        let fence = classify(backend, writable, declaration, disabled);
                        assert_eq!(fence.name(), "none");
                        assert_eq!(fence.word(), crate::program::INIT_FENCE_NONE);
                    }
                }
            }
        }
    }
}
