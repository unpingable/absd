//! The existing NIC owner performs bounded, nonblocking unauthenticated SNTP.
//! Clock write authority stays here; session children receive no Clock object.
use absd_net::{
    Link, Stack,
    datagram::{self, Address, Endpoint, Grant},
    sntp::poller::{Action, Poller},
};
use std::sync::atomic::{AtomicBool, Ordering};
fn note(message: &str) {
    crate::oplog::line(message.to_string());
}
static ENABLED: AtomicBool = AtomicBool::new(false);
static REQUEST: AtomicBool = AtomicBool::new(false);
static MANUAL_RESET: AtomicBool = AtomicBool::new(false);
fn entropy(out: &mut [u8]) -> Result<(), ()> {
    getrandom::fill(out).map_err(|_| ())
}
fn ticks_for_seconds(s: u64) -> u64 {
    s * 3_579_545 / (1193 * 3)
}
pub fn operator(words: &str) -> Result<String, String> {
    use crate::time_policy::Request;
    match crate::time_policy::request(words).map_err(str::to_string)? {
        Request::Status => {
            let i = absd_runtime::civil_clock::info()
                .map_err(|e| format!("clock status refused ({e})\n"))?;
            Ok(format!(
                "{} provider_enabled={} boot_only=yes\n",
                i.status(absd_runtime::hardware_rtc_seconds()),
                ENABLED.load(Ordering::Relaxed)
            ))
        }
        Request::Set(ns) => {
            let seconds = ns / 1_000_000_000;
            absd_runtime::civil_clock::set_sample(ns,absd_runtime::ticks(),2,[0;4],0,0,0).map_err(|e|format!("clock: operator set refused ({e}); supported range 1970..2099, owner grant required\n"))?;
            MANUAL_RESET.store(true, Ordering::Relaxed);
            REQUEST.store(false, Ordering::Relaxed);
            note(&format!(
                "clock: operator asserted Unix seconds={seconds}; software boot-local correction"
            ));
            Ok("clock: software civil time set; operator assertion, RTC unchanged, monotonic deadlines unchanged\n".into())
        }
        Request::Sync => {
            if !ENABLED.load(Ordering::Relaxed) {
                return Err("clock: network synchronization disabled or no NIC; configure /etc/time.conf and restart\n".into());
            }
            REQUEST.store(true, Ordering::Relaxed);
            Ok(
                "clock: bounded synchronization scheduled; inspect date --status for result\n"
                    .into(),
            )
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Retry {
    Carrier,
    Timeout,
    Interval,
}
pub struct Service {
    config: crate::etc::Time,
    poller: Poller,
    endpoint: Option<Endpoint>,
    pending: Option<[u8; 48]>,
    next: u64,
    link_up: bool,
    retry_on_carrier: bool,
    timeout_delay: u64,
    failures: u32,
    suppressed: u32,
    last_notice: Option<(Retry, u64)>,
}
impl Service {
    pub fn new(config: crate::etc::Time) -> Self {
        let enabled =
            config.enabled && config.server.is_some() && absd_runtime::clock_owner_handle() != 0;
        ENABLED.store(enabled, Ordering::Relaxed);
        if config.enabled && !enabled {
            note("clock: configured provider unavailable: no clock-owner grant supplied");
        }
        note(&format!(
            "clock: SNTP enabled={enabled} source=unauthenticated-estimate interval_s={} maximum_step_s={} maximum_age_s={}; TLS policy unchanged",
            config.interval_seconds, config.max_step_seconds, config.max_age_seconds
        ));
        Self {
            config,
            poller: Poller::new(),
            endpoint: None,
            pending: None,
            next: 0,
            link_up: false,
            retry_on_carrier: false,
            timeout_delay: 1000,
            failures: 0,
            suppressed: 0,
            last_notice: None,
        }
    }
    fn close<L: Link>(&mut self, stack: &mut Stack<L>) {
        if let Some(e) = self.endpoint.take() {
            let _ = stack.datagram_close(e);
        }
        self.pending = None;
        self.poller.cancel();
    }
    fn reset_retry(&mut self) {
        self.timeout_delay = 1000;
        self.failures = 0;
        self.suppressed = 0;
        self.last_notice = None;
    }
    fn fail<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        now: u64,
        code: i64,
        reason: &str,
        retry: Retry,
    ) {
        self.close(stack);
        self.failures = self.failures.saturating_add(1);
        let interval = self.config.interval_seconds * 1000;
        let pause = match retry {
            Retry::Carrier => {
                self.retry_on_carrier = true;
                self.timeout_delay = 1000;
                u64::MAX
            }
            Retry::Timeout => {
                let pause = self.timeout_delay.min(interval);
                self.timeout_delay = pause.saturating_mul(2).min(interval);
                pause
            }
            Retry::Interval => {
                self.timeout_delay = 1000;
                interval
            }
        };
        self.next = now.saturating_add(pause);
        let record_error = absd_runtime::civil_clock::failure(
            self.config.server.unwrap_or([0; 4]),
            self.config.server_port,
            code,
        )
        .err();
        let notice = self
            .last_notice
            .is_none_or(|(kind, at)| kind != retry || now.saturating_sub(at) >= 60_000);
        if notice {
            let state = match retry {
                Retry::Carrier => "waiting for carrier",
                Retry::Timeout => "retrying after timeout",
                Retry::Interval => "waiting normal retry interval",
            };
            let when = if retry == Retry::Carrier {
                "retry_on=carrier".to_string()
            } else {
                format!("retry_delay_ms={pause}")
            };
            note(&format!(
                "clock: {state}; code={code} reason={reason} failed_attempts={} suppressed={} {when} status_update_error={record_error:?}; last successful source retained",
                self.failures, self.suppressed
            ));
            self.suppressed = 0;
            self.last_notice = Some((retry, now));
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
    }
    pub fn poll<L: Link>(&mut self, stack: &mut Stack<L>, link_available: bool) {
        let now = absd_runtime::boot_millis();
        let carrier_rising = link_available && !self.link_up;
        self.link_up = link_available;
        let manual_reset = MANUAL_RESET.swap(false, Ordering::Relaxed);
        if manual_reset {
            self.reset_retry();
            self.retry_on_carrier = false;
            self.close(stack);
            self.next = now.saturating_add(self.config.interval_seconds * 1000);
        }
        if !ENABLED.load(Ordering::Relaxed) {
            return;
        }
        // Carrier may settle after the first startup pass. Do not carry a
        // link-unavailable interval into the recovered link. A simultaneous
        // manual assertion keeps its explicit automatic-work cancellation.
        if carrier_rising && self.retry_on_carrier && !manual_reset && !self.poller.active() {
            self.retry_on_carrier = false;
            self.next = now;
        }
        let requested = REQUEST.swap(false, Ordering::Relaxed);
        if requested && !self.poller.active() {
            self.next = now;
        }
        if !link_available {
            if self.poller.active() || now >= self.next {
                self.fail(stack, now, -100, "link unavailable", Retry::Carrier);
                self.retry_on_carrier = true;
            }
            return;
        }
        let action = if !self.poller.active() {
            if now < self.next {
                return;
            }
            let grant = Grant {
                local_port: self.config.local_port,
                peer: Address {
                    ip: self.config.server.unwrap(),
                    port: self.config.server_port,
                },
            };
            match stack.datagram_bind(grant) {
                Ok(e) => self.endpoint = Some(e),
                Err(e) => {
                    self.fail(stack, now, -5, &format!("endpoint {e:?}"), Retry::Interval);
                    return;
                }
            }
            self.poller.start(now, entropy)
        } else {
            let mut bytes = [0u8; 48];
            let packet = match stack.datagram_receive(self.endpoint.unwrap(), &mut bytes) {
                Ok((n, _)) => Some(n),
                Err(datagram::Error::Again) => None,
                Err(e) => {
                    self.fail(stack, now, -5, &format!("receive {e:?}"), Retry::Interval);
                    return;
                }
            };
            self.poller.step(now, packet.map(|n| &bytes[..n]), entropy)
        };
        match action {
            Action::None => {}
            Action::Send(bytes) => self.pending = Some(bytes),
            Action::Failed(error) => {
                let code = match error {
                    absd_net::sntp::Error::Timeout | absd_net::sntp::Error::Late => -110,
                    absd_net::sntp::Error::Refused(_) | absd_net::sntp::Error::Retired => -22,
                    _ => -5,
                };
                let retry = if matches!(
                    error,
                    absd_net::sntp::Error::Timeout | absd_net::sntp::Error::Late
                ) {
                    Retry::Timeout
                } else {
                    // KoD, stratum refusal and malformed replies must not
                    // turn the acquisition retry into a one-packet/s loop.
                    Retry::Interval
                };
                self.fail(stack, now, code, &format!("{error:?}"), retry);
                return;
            }
            Action::Accepted { claim, rtt_ms } => {
                let ns = claim.unix_seconds * 1_000_000_000
                    + ((u64::from(claim.fraction_2p32) * 1_000_000_000) >> 32);
                let previous = match absd_runtime::civil_clock::info() {
                    Ok(i) => (i.unix_ns, i.source),
                    Err(e) => {
                        self.fail(
                            stack,
                            now,
                            e,
                            "current clock unavailable for step policy",
                            Retry::Interval,
                        );
                        return;
                    }
                };
                if !crate::time_policy::accepts_step(
                    previous.0,
                    previous.1 == absd_runtime::civil_clock::RTC,
                    ns,
                    self.config.max_step_seconds,
                ) {
                    self.fail(stack, now, -34, "maximum-step bound", Retry::Interval);
                    return;
                }
                let result = absd_runtime::civil_clock::set_sample(
                    ns,
                    absd_runtime::ticks(),
                    3,
                    self.config.server.unwrap(),
                    self.config.server_port,
                    rtt_ms,
                    ticks_for_seconds(self.config.max_age_seconds),
                );
                if let Err(e) = result {
                    self.fail(stack, now, e, "kernel correction refused", Retry::Interval);
                    return;
                }
                self.reset_retry();
                note(&format!(
                    "clock: accepted unauthenticated SNTP estimate seconds={} rtt_ms={rtt_ms}; UTC uncertainty unknown, RTC/TLS unchanged",
                    claim.unix_seconds
                ));
                self.close(stack);
                self.next = now.saturating_add(self.config.interval_seconds * 1000);
                return;
            }
        }
        if let Some(packet) = self.pending {
            match stack.datagram_send(
                self.endpoint.unwrap(),
                Address {
                    ip: self.config.server.unwrap(),
                    port: self.config.server_port,
                },
                &packet,
            ) {
                Ok(()) => self.pending = None,
                Err(datagram::Error::Again) => {}
                Err(e) => {
                    self.fail(stack, now, -5, &format!("send {e:?}"), Retry::Interval);
                }
            }
        }
    }
}
