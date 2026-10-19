//! Pure NVMe readiness rules; register observations remain the driver's job.

pub const CC_ENABLE: u32 = 1;
pub const CC_CRIME: u32 = 1 << 24;
pub const CSTS_READY: u32 = 1;
const VERSION_2: u32 = 0x0002_0000;
const CRWMS: u64 = 1 << 59;
const CRIMS: u64 = 1 << 60;

/// CRTO fields are reserved for legacy readiness; do not consume them there.
pub fn uses_crto(version: u32, capabilities: u64) -> bool {
    version >= VERSION_2 && capabilities & CRWMS != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timeouts {
    pub with_media: u64,
    independent: u64,
}

impl Timeouts {
    /// Controller-reported 500 ms units, converted to the existing PIT ticks.
    /// Keep the CAP.TO floor even if a newer field reports a smaller bound.
    pub fn from_registers(version: u32, capabilities: u64, crto: Option<u32>) -> Self {
        let legacy = (((capabilities >> 24) & 0xff) * 500).max(500);
        let mut limits = Self {
            with_media: legacy,
            independent: legacy,
        };
        if uses_crto(version, capabilities)
            && let Some(value) = crto
        {
            limits.with_media = limits.with_media.max(u64::from(value & 0xffff) * 500);
            if capabilities & CRIMS != 0 {
                limits.independent = limits.independent.max(u64::from(value >> 16) * 500);
                // With-media readiness includes independent readiness. A
                // contradictory report must not make the wait shorter.
                limits.with_media = limits.with_media.max(limits.independent);
            } else {
                limits.independent = limits.with_media;
            }
        }
        limits
    }

    pub fn for_configuration(self, configuration: u32) -> u64 {
        if configuration & CC_CRIME != 0 {
            self.independent
        } else {
            self.with_media
        }
    }
}

/// Clearing EN is defined only after an enabled controller reports RDY=1.
pub fn may_clear_enable(configuration: u32, status: u32) -> bool {
    configuration & CC_ENABLE != 0 && status & CSTS_READY != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_and_reserved_crto_values_do_not_extend_the_wait() {
        let capabilities = 7 << 24;
        for version in [0x0001_0400, VERSION_2] {
            let limits = Timeouts::from_registers(version, capabilities, Some(u32::MAX));
            assert_eq!(limits.with_media, 3_500);
            assert_eq!(limits.for_configuration(CC_CRIME), 3_500);
        }
        assert!(!uses_crto(0x0001_0400, CRWMS | CRIMS));
        assert!(!uses_crto(VERSION_2, CRIMS));
        assert_eq!(Timeouts::from_registers(0, 0, None).with_media, 500);
    }

    #[test]
    fn version_two_modes_use_the_larger_applicable_report() {
        let capabilities = CRWMS | CRIMS | (2 << 24);
        let limits = Timeouts::from_registers(VERSION_2, capabilities, Some((6 << 16) | 300));
        assert_eq!(limits.with_media, 150_000);
        assert_eq!(limits.for_configuration(CC_CRIME | CC_ENABLE), 3_000);
        let shorter = Timeouts::from_registers(VERSION_2, capabilities, Some((1 << 16) | 1));
        assert_eq!(shorter.with_media, 1_000);
        assert_eq!(shorter.for_configuration(CC_CRIME), 1_000);
    }

    #[test]
    fn unsupported_independent_mode_and_full_field_bounds_are_explicit() {
        let media_only = Timeouts::from_registers(VERSION_2, CRWMS, Some(0xffff_000a));
        assert_eq!(media_only.with_media, 5_000);
        assert_eq!(media_only.for_configuration(CC_CRIME), 5_000);
        let maximum = Timeouts::from_registers(VERSION_2, CRWMS | CRIMS, Some(u32::MAX));
        assert_eq!(maximum.with_media, 32_767_500);
        assert_eq!(maximum.for_configuration(CC_CRIME), 32_767_500);
        let contradictory =
            Timeouts::from_registers(VERSION_2, CRWMS | CRIMS, Some((20 << 16) | 1));
        assert_eq!(contradictory.with_media, 10_000);
    }

    #[test]
    fn enabling_and_disabling_states_never_authorize_an_early_clear() {
        for enabled in [false, true] {
            for ready in [false, true] {
                let configuration = u32::from(enabled) * CC_ENABLE;
                let status = u32::from(ready) * CSTS_READY;
                assert_eq!(may_clear_enable(configuration, status), enabled && ready);
            }
        }
        assert!(!may_clear_enable(CC_ENABLE, 0));
    }
}
