//! Trusted, compile-time fixture selectors mirrored from the sealed case manifest.
//! Contains case data only; it does not construct TLS configuration or authority.
// scripts/native-tls-cases.json SHA256 1f40088c002304179f250b1dcc7248692df15ae9854aa407f97de133ed27a761

#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub id: &'static str,
    pub local_port: u16,
    pub expected_body: usize,
    pub grant_lifetime_ms: u64,
    pub connect_timeout_ms: u64,
    pub missing_time: bool,
    pub interrupt_after: Option<&'static str>,
    pub interrupt_delay_ms: u64,
    pub requested_peer_port: u16,
    pub grant_exhaustion: bool,
    pub pause_before_response_ms: u64,
}

pub const CASES: &[Case] = &[
    Case { id: "P01", local_port: 7300, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P01/empty", local_port: 7301, expected_body: 0, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P02", local_port: 7302, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P02b", local_port: 7303, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P03", local_port: 7304, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P04", local_port: 7305, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P05", local_port: 7306, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P08", local_port: 7307, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P09/none", local_port: 7308, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P09/h2-only", local_port: 7309, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P11", local_port: 7310, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: true, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W01", local_port: 7311, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W02", local_port: 7312, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W03", local_port: 7313, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W04", local_port: 7314, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W05/header1", local_port: 7315, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W05/header4", local_port: 7316, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W05/body", local_port: 7317, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "W06", local_port: 7318, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "L01", local_port: 7319, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "L02", local_port: 7320, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "L03", local_port: 7321, expected_body: 16384, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 1000 },
    Case { id: "L04/handshake", local_port: 7322, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: Some("TLS CLIENT HANDSHAKE START"), interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "L04/authenticated", local_port: 7323, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: Some("TLS CLIENT AUTHENTICATED"), interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "L04/full-rx", local_port: 7324, expected_body: 16384, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: Some("TLS READ PAUSE"), interrupt_delay_ms: 1000, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 2000 },
    Case { id: "L05", local_port: 7325, expected_body: 2048, grant_lifetime_ms: 500, connect_timeout_ms: 500, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "L07", local_port: 7326, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4444, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "L09", local_port: 7327, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: true, pause_before_response_ms: 0 },
    Case { id: "H01/max", local_port: 7328, expected_body: 16384, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H01/header-over", local_port: 7329, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H01/body-over", local_port: 7330, expected_body: 16384, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H02/duplicate", local_port: 7331, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H02/conflicting", local_port: 7332, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H02/nondecimal", local_port: 7333, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H02/overflow", local_port: 7334, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H03/transfer-encoding", local_port: 7335, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H03/interim", local_port: 7336, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H03/redirect", local_port: 7337, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H03/content-encoding", local_port: 7338, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H04", local_port: 7339, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "H05", local_port: 7340, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
    Case { id: "P10", local_port: 7341, expected_body: 2048, grant_lifetime_ms: 15000, connect_timeout_ms: 2000, missing_time: false, interrupt_after: None, interrupt_delay_ms: 0, requested_peer_port: 4443, grant_exhaustion: false, pause_before_response_ms: 0 },
];

pub fn find(id: &str) -> Option<Case> {
    CASES.iter().copied().find(|case| case.id == id)
}
