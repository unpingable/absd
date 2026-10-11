//! Architectural topology decoding, independent of AP bootstrap policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuTopology {
    pub apic: u32,
    pub package: u32,
    pub core: u32,
    pub smt_shift: u8,
}
#[derive(Clone, Copy)]
pub struct Level {
    pub shift: u8,
    pub count: u16,
    pub kind: u8,
    pub apic: u32,
}
pub fn decode(levels: &[Level]) -> Option<CpuTopology> {
    let first = *levels.first()?;
    let mut smt = None;
    let mut core = None;
    let mut previous = 0;
    let mut package_shift = 0;
    let mut previous_count = 0;
    for l in levels {
        if l.count == 0
            || l.kind == 0
            || l.shift > 31
            || l.shift < previous
            || l.count < previous_count
            || l.apic != first.apic
            || u32::from(l.count) > (1u32 << l.shift)
        {
            return None;
        }
        match l.kind {
            1 => {
                if smt.replace(l.shift).is_some() {
                    return None;
                }
            }
            2 => {
                if core.replace(l.shift).is_some() || smt.is_none() {
                    return None;
                }
            }
            3..=6 => {
                core?;
            }
            _ => return None,
        }
        previous = l.shift;
        previous_count = l.count;
        package_shift = l.shift;
    }
    let smt = smt?;
    core?;
    Some(CpuTopology {
        apic: first.apic,
        package: first.apic >> package_shift,
        core: (first.apic & ((1u32 << package_shift) - 1)) >> smt,
        smt_shift: smt,
    })
}
impl CpuTopology {
    pub fn same_core(self, other: Self) -> bool {
        self.package == other.package && self.core == other.core
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn topology(apic: u32, smt: u8, package: u8) -> CpuTopology {
        decode(&[
            Level {
                shift: smt,
                count: 1 << smt,
                kind: 1,
                apic,
            },
            Level {
                shift: package,
                count: 1 << package,
                kind: 2,
                apic,
            },
        ])
        .unwrap()
    }
    #[test]
    fn separate_core_sibling_and_package_holes() {
        assert!(!topology(0, 0, 1).same_core(topology(1, 0, 1)));
        assert!(topology(0, 1, 3).same_core(topology(1, 1, 3)));
        assert!(!topology(0, 1, 3).same_core(topology(8, 1, 3)));
        assert_eq!(topology(14, 1, 4).core, 7);
    }
    #[test]
    fn inconsistent_topology_refused() {
        assert!(
            decode(&[Level {
                shift: 0,
                count: 2,
                kind: 1,
                apic: 0
            }])
            .is_none()
        );
        assert!(
            decode(&[
                Level {
                    shift: 1,
                    count: 2,
                    kind: 1,
                    apic: 0
                },
                Level {
                    shift: 2,
                    count: 4,
                    kind: 2,
                    apic: 1
                }
            ])
            .is_none()
        );
        assert!(
            decode(&[Level {
                shift: 2,
                count: 4,
                kind: 2,
                apic: 0
            }])
            .is_none()
        );
    }
    #[test]
    fn descending_counts_and_reversed_domains_refused() {
        assert!(
            decode(&[
                Level {
                    shift: 1,
                    count: 2,
                    kind: 1,
                    apic: 0
                },
                Level {
                    shift: 2,
                    count: 1,
                    kind: 2,
                    apic: 0
                }
            ])
            .is_none()
        );
        assert!(
            decode(&[
                Level {
                    shift: 1,
                    count: 2,
                    kind: 2,
                    apic: 0
                },
                Level {
                    shift: 2,
                    count: 4,
                    kind: 1,
                    apic: 0
                }
            ])
            .is_none()
        );
    }
}
