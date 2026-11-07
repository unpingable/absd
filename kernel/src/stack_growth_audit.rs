//! Private normal-suite accounting for committed grow-down stack mappings.

#[derive(Clone, Copy)]
pub enum Role {
    Ordinary,
    StackGrowProbe,
    OverflowProbe,
}

#[derive(Clone, Copy, Default)]
pub struct StackGrowthAudit {
    pub terminals: u64,
    pub terminal_pages: u64,
    pub ordinary_pages: u64,
    pub grow_probes: u64,
    pub grow_probe_pages: u64,
    pub overflow_probes: u64,
    pub overflow_probe_pages: u64,
    pub invalid: bool,
}

impl StackGrowthAudit {
    pub const EMPTY: Self = Self {
        terminals: 0,
        terminal_pages: 0,
        ordinary_pages: 0,
        grow_probes: 0,
        grow_probe_pages: 0,
        overflow_probes: 0,
        overflow_probe_pages: 0,
        invalid: false,
    };

    /// Accumulate terminal observations independently of the successful-map
    /// counter. A bad sum makes the audit permanently invalid, never wrapped.
    fn record(&mut self, role: Role, pages: u64) {
        if self.invalid {
            return;
        }
        if let Some(next) = self.with_record(role, pages) {
            *self = next;
        } else {
            self.invalid = true;
        }
    }

    pub fn record_stack(&mut self, role: Role, top: u64, bottom: u64, initial_pages: u64) {
        if !top.is_multiple_of(4096) || !bottom.is_multiple_of(4096) {
            self.invalid = true;
            return;
        }
        let Some(pages) = top
            .checked_sub(bottom)
            .and_then(|bytes| (bytes / 4096).checked_sub(initial_pages))
        else {
            self.invalid = true;
            return;
        };
        self.record(role, pages);
    }

    fn with_record(mut self, role: Role, pages: u64) -> Option<Self> {
        self.terminals = self.terminals.checked_add(1)?;
        self.terminal_pages = self.terminal_pages.checked_add(pages)?;
        match role {
            Role::Ordinary => self.ordinary_pages = self.ordinary_pages.checked_add(pages)?,
            Role::StackGrowProbe => {
                self.grow_probes = self.grow_probes.checked_add(1)?;
                self.grow_probe_pages = self.grow_probe_pages.checked_add(pages)?;
            }
            Role::OverflowProbe => {
                self.overflow_probes = self.overflow_probes.checked_add(1)?;
                self.overflow_probe_pages = self.overflow_probe_pages.checked_add(pages)?;
            }
        }
        Some(self)
    }

    /// The dedicated probes retain their exact claims. Other programs may
    /// also grow stacks, but every committed page and real terminal must be
    /// accounted for; ordinary growth cannot compensate for a short probe.
    pub fn passes(&self, successful_pages: u64, terminals: u64, overflow_pages: u64) -> bool {
        let categories = self
            .ordinary_pages
            .checked_add(self.grow_probe_pages)
            .and_then(|sum| sum.checked_add(self.overflow_probe_pages));
        !self.invalid
            && self.terminals == terminals
            && self.terminal_pages == successful_pages
            && categories == Some(successful_pages)
            && self.grow_probes == 1
            && self.grow_probe_pages == 9
            && self.overflow_probes == 1
            && self.overflow_probe_pages == overflow_pages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probes(grow: u64, overflow: u64) -> StackGrowthAudit {
        let mut audit = StackGrowthAudit::EMPTY;
        audit.record(Role::StackGrowProbe, grow);
        audit.record(Role::OverflowProbe, overflow);
        audit
    }

    #[test]
    fn legitimate_ordinary_stack_use_is_accounted_without_a_fixed_total() {
        // Address-window, guard and frame ceilings remain separate checks.
        for ordinary in [0, 1, 7, 100] {
            let mut audit = probes(9, 1022);
            audit.record(Role::Ordinary, ordinary);
            assert!(audit.passes(1031 + ordinary, 3, 1022));
        }
    }

    #[test]
    fn missing_either_probe_is_refused() {
        for (role, pages) in [(Role::StackGrowProbe, 9), (Role::OverflowProbe, 1022)] {
            let mut audit = StackGrowthAudit::EMPTY;
            audit.record(role, pages);
            assert!(!audit.passes(pages, 1, 1022));
        }
    }

    #[test]
    fn duplicate_either_probe_is_refused_even_with_a_matching_sum() {
        for (role, pages) in [(Role::StackGrowProbe, 9), (Role::OverflowProbe, 1022)] {
            let mut audit = probes(9, 1022);
            audit.record(role, pages);
            assert!(!audit.passes(1031 + pages, 3, 1022));
        }
    }

    #[test]
    fn wrong_probe_distribution_cannot_hide_behind_the_old_aggregate() {
        assert!(!probes(8, 1023).passes(1031, 2, 1022));
    }

    #[test]
    fn ordinary_growth_cannot_compensate_for_a_short_overflow_probe() {
        let mut audit = probes(9, 1021);
        audit.record(Role::Ordinary, 8);
        assert!(!audit.passes(1038, 3, 1022));
    }

    #[test]
    fn independent_successful_map_count_must_match_terminal_growth() {
        let audit = probes(9, 1022);
        assert!(!audit.passes(1030, 2, 1022));
        assert!(!audit.passes(1032, 2, 1022));
    }

    #[test]
    fn every_real_spawn_requires_one_terminal_observation() {
        let audit = probes(9, 1022);
        assert!(!audit.passes(1031, 1, 1022));
        assert!(!audit.passes(1031, 3, 1022));
    }

    #[test]
    fn checked_overflow_is_sticky_and_cannot_pass() {
        let mut audit = StackGrowthAudit::EMPTY;
        audit.record(Role::Ordinary, u64::MAX);
        audit.record(Role::StackGrowProbe, 9);
        audit.record(Role::OverflowProbe, 1022);
        assert!(audit.invalid);
        assert!(!audit.passes(1031, 3, 1022));
    }

    #[test]
    fn construction_probe_snapshot_is_restored_before_real_terminals() {
        let mut audit = StackGrowthAudit::EMPTY;
        let saved = audit;
        audit.record(Role::Ordinary, 0);
        audit = saved;
        audit.record(Role::StackGrowProbe, 9);
        audit.record(Role::OverflowProbe, 1022);
        assert!(audit.passes(1031, 2, 1022));
    }

    #[test]
    fn invalid_or_short_stack_bounds_invalidate_the_audit() {
        for (top, bottom) in [(4096, 8192), (8192, 4096), (12289, 4096), (12288, 4097)] {
            let mut audit = probes(9, 1022);
            audit.record_stack(Role::Ordinary, top, bottom, 2);
            assert!(audit.invalid, "top={top} bottom={bottom}");
            assert!(!audit.passes(1031, 3, 1022));
        }
    }

    #[test]
    fn valid_committed_bounds_feed_the_same_independent_conservation_check() {
        let mut audit = StackGrowthAudit::EMPTY;
        audit.record_stack(Role::StackGrowProbe, 11 * 4096, 0, 2);
        audit.record_stack(Role::OverflowProbe, 1024 * 4096, 0, 2);
        audit.record_stack(Role::Ordinary, 9 * 4096, 0, 2);
        assert!(audit.passes(1038, 3, 1022));
    }
}
