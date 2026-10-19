//! One selected fresh-boot occurrence. CASES.json is the qualification contract.
#[derive(Clone, Copy)]
pub struct Case {
    pub id: &'static str,
    pub local_port: u16,
    pub grant_lifetime_ms: u64,
    pub missing_time: bool,
    pub missing_output: bool,
    pub queue_control: bool,
    pub suppress_reply: bool,
    pub interrupt_phase: Option<&'static str>,
    pub interrupt_delay_ms: u64,
}
pub fn find(id: &str) -> Option<Case> {
    let ordinal = id.strip_prefix("Q")?.parse::<u16>().ok()?;
    if (ordinal == 0 || ordinal > 31) || id != format!("Q{ordinal:02}") {
        return None;
    }
    Some(Case {
        id: IDS[(ordinal - 1) as usize],
        local_port: 7799 + ordinal,
        grant_lifetime_ms: if ordinal == 23 { 3000 } else { 15000 },
        missing_time: ordinal == 30,
        missing_output: ordinal == 29,
        queue_control: ordinal == 19,
        suppress_reply: ordinal == 20,
        interrupt_phase: match ordinal {
            21 => Some("Handshake"),
            22 => Some("Stream"),
            _ => None,
        },
        interrupt_delay_ms: match ordinal {
            21 => 1000,
            22 => 300,
            _ => 0,
        },
    })
}
const IDS: [&str; 31] = [
    "Q01", "Q02", "Q03", "Q04", "Q05", "Q06", "Q07", "Q08", "Q09", "Q10", "Q11", "Q12", "Q13",
    "Q14", "Q15", "Q16", "Q17", "Q18", "Q19", "Q20", "Q21", "Q22", "Q23", "Q24", "Q25", "Q26",
    "Q27", "Q28", "Q29", "Q30", "Q31",
];
