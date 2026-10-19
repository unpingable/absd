//! Bounded USB2 boot-keyboard selection and report translation.
//! Pure rules used by the native controller and exercised on the host.

use crate::xhci_ring::{COMPLETION_SUCCESS, Event, SPEED_FULL, SPEED_HIGH, SPEED_LOW};

pub const CONFIG_BYTES: usize = 1024;
pub const REPORT_BYTES: usize = 8;

/// Observations required before a successor may overwrite retired DMA pages.
/// These are observations supplied by the driver, not a hardware fence proof.
#[derive(Clone, Copy, Debug)]
pub struct Reclaim {
    pub halted: bool,
    pub bus_master: bool,
    pub reset_complete: bool,
    pub irq_pending: bool,
    pub quiet_unchanged: bool,
}

impl Reclaim {
    pub fn permitted(self) -> bool {
        self.halted
            && !self.bus_master
            && self.reset_complete
            && !self.irq_pending
            && self.quiet_unchanged
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Configuration,
    Truncated,
    DescriptorLength,
    Interface,
    Endpoint,
    Hid,
    Ambiguous,
    Speed,
    Interval,
    ReportLength,
    ReportError,
    CompletionIdentity,
    CompletionCode(u8),
    CompletionResidual(u32),
    RetirementUncertain,
    ResetTimeout,
}

/// Match the one outstanding normal-IN TD. IRQ counts do not identify it.
pub fn completion(event: Event, trb: u64, slot: u8, endpoint: u8) -> Result<(), Error> {
    if trb == 0
        || !trb.is_multiple_of(16)
        || slot == 0
        || !(3..=31).contains(&endpoint)
        || endpoint & 1 == 0
    {
        return Err(Error::CompletionIdentity);
    }
    let Event::Transfer {
        trb: actual,
        code,
        residual,
        slot: actual_slot,
        endpoint: actual_endpoint,
        event_data: false,
    } = event
    else {
        return Err(Error::CompletionIdentity);
    };
    if actual != trb || actual_slot != slot || actual_endpoint != endpoint {
        return Err(Error::CompletionIdentity);
    }
    if code != COMPLETION_SUCCESS {
        return Err(Error::CompletionCode(code));
    }
    if residual != 0 {
        return Err(Error::CompletionResidual(residual));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub address: u8,
    pub packet: u16,
    /// xHCI exponent in microframes, not USB's bInterval.
    pub interval: u8,
}

impl Endpoint {
    pub fn parse(bytes: &[u8], speed: u8) -> Result<Self, Error> {
        if bytes.len() < 7 || usize::from(bytes[0]) != bytes.len() || bytes[1] != 5 {
            return Err(Error::DescriptorLength);
        }
        let address = bytes[2];
        let packet = u16::from_le_bytes([bytes[4], bytes[5]]);
        if address & 0xf0 != 0x80 || address & 15 == 0 || bytes[3] != 3 {
            return Err(Error::Endpoint);
        }
        let max = match speed {
            SPEED_LOW => 8,
            SPEED_FULL => 64,
            SPEED_HIGH => 1024,
            _ => return Err(Error::Speed),
        };
        if !(8..=max).contains(&packet) {
            return Err(Error::Endpoint);
        }
        let interval = match (speed, bytes[6]) {
            (_, 0) => return Err(Error::Interval),
            (SPEED_LOW, 1..=9) => return Err(Error::Interval),
            (SPEED_HIGH, 1..=16) => bytes[6] - 1,
            (SPEED_HIGH, _) => return Err(Error::Interval),
            (_, period) => (15 - (u16::from(period) * 8).leading_zeros()) as u8,
        };
        Ok(Self {
            address,
            packet,
            interval,
        })
    }

    pub fn dci(self) -> u8 {
        2 * (self.address & 15) + 1
    }

    /// First five DWORDs of a zeroed xHCI interrupt-IN endpoint context.
    pub fn context(self, ring: u64) -> [u32; 5] {
        assert!(ring.is_multiple_of(16));
        [
            u32::from(self.interval) << 16,
            (u32::from(self.packet) << 16) | (7 << 3) | (3 << 1),
            ring as u32 | 1,
            (ring >> 32) as u32,
            (u32::from(self.packet) << 16) | REPORT_BYTES as u32,
        ]
    }
}

pub const fn setup(kind: u8, request: u8, value: u16, interface: u16, length: u16) -> u64 {
    (kind as u64)
        | ((request as u64) << 8)
        | ((value as u64) << 16)
        | ((interface as u64) << 32)
        | ((length as u64) << 48)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Keyboard {
    pub configuration: u8,
    pub interface: u8,
    pub endpoint: Endpoint,
}

struct Interface {
    number: u8,
    keyboard: bool,
    expected_endpoints: u8,
    endpoints: u8,
    addresses: u32,
    input: Option<Endpoint>,
    hid: bool,
}

impl Interface {
    fn finish(&self, configuration: u8, selected: &mut Option<Keyboard>) -> Result<(), Error> {
        if self.endpoints != self.expected_endpoints {
            return Err(Error::Interface);
        }
        if self.keyboard {
            if !self.hid {
                return Err(Error::Hid);
            }
            let endpoint = self.input.ok_or(Error::Endpoint)?;
            if selected.is_some() {
                return Err(Error::Ambiguous);
            }
            *selected = Some(Keyboard {
                configuration,
                interface: self.number,
                endpoint,
            });
        }
        Ok(())
    }
}

/// Device-local selection policy. Unsupported or malformed descriptors do not
/// stop a controller scan. Transport and ownership failures are handled by the
/// caller before this pure selector runs.
pub fn supported_configuration(bytes: &[u8], speed: u8) -> Option<Keyboard> {
    select(bytes, speed).ok().flatten()
}

/// Validate the complete configuration, including tails after a match.
pub fn select(bytes: &[u8], speed: u8) -> Result<Option<Keyboard>, Error> {
    if bytes.len() < 9 || bytes.len() > CONFIG_BYTES || bytes[0] != 9 || bytes[1] != 2 {
        return Err(Error::Configuration);
    }
    let total = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    if total != bytes.len() || bytes[4] == 0 || bytes[5] == 0 || bytes[7] & 0x80 == 0 {
        return Err(Error::Configuration);
    }
    let mut at = 9;
    let mut current: Option<Interface> = None;
    let mut selected = None;
    // At most (1024 - 9) / 9 interface descriptors fit. Storing their
    // identities also bounds duplicate-setting checks without allocation.
    let mut settings = [0u16; (CONFIG_BYTES - 9) / 9];
    let mut setting_count = 0;
    let mut interfaces = [0u64; 4];
    let mut default_interfaces = [0u64; 4];
    while at < bytes.len() {
        if bytes.len() - at < 2 {
            return Err(Error::Truncated);
        }
        let length = usize::from(bytes[at]);
        if length < 2 {
            return Err(Error::DescriptorLength);
        }
        let next = at
            .checked_add(length)
            .filter(|&n| n <= total)
            .ok_or(Error::Truncated)?;
        let descriptor = &bytes[at..next];
        match descriptor[1] {
            2 => return Err(Error::Configuration),
            4 => {
                if length < 9 {
                    return Err(Error::DescriptorLength);
                }
                if let Some(previous) = current.take() {
                    previous.finish(bytes[5], &mut selected)?;
                }
                let number = descriptor[2];
                let alternate = descriptor[3];
                if number >= bytes[4] {
                    return Err(Error::Interface);
                }
                let identity = (u16::from(number) << 8) | u16::from(alternate);
                if settings[..setting_count].contains(&identity) || setting_count == settings.len()
                {
                    return Err(Error::Interface);
                }
                settings[setting_count] = identity;
                setting_count += 1;
                interfaces[usize::from(number / 64)] |= 1 << (number % 64);
                if alternate == 0 {
                    default_interfaces[usize::from(number / 64)] |= 1 << (number % 64);
                }
                current = Some(Interface {
                    number,
                    keyboard: alternate == 0 && descriptor[5..8] == [3, 1, 1],
                    expected_endpoints: descriptor[4],
                    endpoints: 0,
                    addresses: 0,
                    input: None,
                    hid: false,
                });
            }
            5 => {
                if length < 7 {
                    return Err(Error::DescriptorLength);
                }
                let interface = current.as_mut().ok_or(Error::Interface)?;
                let address = descriptor[2];
                if address & 0x70 != 0 || address & 15 == 0 {
                    return Err(Error::Endpoint);
                }
                let bit = 1 << ((address & 15) + if address & 0x80 != 0 { 16 } else { 0 });
                if interface.addresses & bit != 0 {
                    return Err(Error::Endpoint);
                }
                interface.addresses |= bit;
                interface.endpoints = interface.endpoints.checked_add(1).ok_or(Error::Endpoint)?;
                if interface.keyboard && address & 0x80 != 0 {
                    if interface.input.is_some() {
                        return Err(Error::Endpoint);
                    }
                    interface.input = Some(Endpoint::parse(descriptor, speed)?);
                }
            }
            0x21 if current.as_ref().is_some_and(|i| i.keyboard) => {
                let interface = current.as_mut().unwrap();
                if length < 9
                    || interface.hid
                    || descriptor[5] == 0
                    || 6 + usize::from(descriptor[5]) * 3 > length
                {
                    return Err(Error::Hid);
                }
                let mut report = false;
                for entry in descriptor[6..6 + usize::from(descriptor[5]) * 3]
                    .as_chunks::<3>()
                    .0
                {
                    if entry[0] == 0x22 {
                        if report || u16::from_le_bytes([entry[1], entry[2]]) == 0 {
                            return Err(Error::Hid);
                        }
                        report = true;
                    }
                }
                if !report {
                    return Err(Error::Hid);
                }
                interface.hid = true;
            }
            _ => {}
        }
        at = next;
    }
    if let Some(previous) = current {
        previous.finish(bytes[5], &mut selected)?;
    }
    if interfaces != default_interfaces
        || interfaces.iter().map(|word| word.count_ones()).sum::<u32>() != u32::from(bytes[4])
    {
        return Err(Error::Interface);
    }
    Ok(selected)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Presses {
    bytes: [u8; 6],
    len: usize,
}

impl Presses {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Default)]
pub struct Reports {
    held: [u8; 6],
    caps: bool,
    pub invalid: u64,
    pub unmapped: u64,
}

impl Reports {
    pub const fn new() -> Self {
        Self {
            held: [0; 6],
            caps: false,
            invalid: 0,
            unmapped: 0,
        }
    }

    /// Clear private key state at a fence, without producing input.
    pub fn fence(&mut self) {
        self.held = [0; 6];
        self.caps = false;
    }

    pub fn translate(&mut self, report: &[u8]) -> Result<Presses, Error> {
        let error = if report.len() != REPORT_BYTES {
            Some(Error::ReportLength)
        } else if report[2..].iter().any(|key| (1..=3).contains(key)) {
            Some(Error::ReportError)
        } else {
            None
        };
        if let Some(error) = error {
            self.invalid = self.invalid.saturating_add(1);
            return Err(error);
        }
        let mut keys = [0; 6];
        let mut count = 0;
        for &key in &report[2..] {
            if key != 0 && !keys[..count].contains(&key) {
                keys[count] = key;
                count += 1;
            }
        }
        if keys.contains(&0x39) && !self.held.contains(&0x39) {
            self.caps = !self.caps;
        }
        let mut out = Presses {
            bytes: [0; 6],
            len: 0,
        };
        for &key in &keys[..count] {
            if self.held.contains(&key) || key == 0x39 {
                continue;
            }
            if let Some(byte) = ascii(key, report[0], self.caps) {
                out.bytes[out.len] = byte;
                out.len += 1;
            } else {
                self.unmapped = self.unmapped.saturating_add(1);
            }
        }
        self.held = keys;
        Ok(out)
    }
}

fn ascii(key: u8, modifiers: u8, caps: bool) -> Option<u8> {
    if modifiers & 0xcc != 0 {
        return None;
    }
    let shift = modifiers & 0x22 != 0;
    if modifiers & 0x11 != 0 {
        return if (4..=29).contains(&key) {
            Some(key - 3)
        } else {
            None
        };
    }
    if (4..=29).contains(&key) {
        return Some(if shift ^ caps { b'A' } else { b'a' } + key - 4);
    }
    if (30..=39).contains(&key) {
        return Some(if shift { b"!@#$%^&*()" } else { b"1234567890" }[usize::from(key - 30)]);
    }
    Some(match key {
        40 => b'\n',
        41 => 0x1b,
        42 => 0x7f,
        43 => b'\t',
        44 => b' ',
        45 => {
            if shift {
                b'_'
            } else {
                b'-'
            }
        }
        46 => {
            if shift {
                b'+'
            } else {
                b'='
            }
        }
        47 => {
            if shift {
                b'{'
            } else {
                b'['
            }
        }
        48 => {
            if shift {
                b'}'
            } else {
                b']'
            }
        }
        49 => {
            if shift {
                b'|'
            } else {
                b'\\'
            }
        }
        51 => {
            if shift {
                b':'
            } else {
                b';'
            }
        }
        52 => {
            if shift {
                b'"'
            } else {
                b'\''
            }
        }
        53 => {
            if shift {
                b'~'
            } else {
                b'`'
            }
        }
        54 => {
            if shift {
                b'<'
            } else {
                b','
            }
        }
        55 => {
            if shift {
                b'>'
            } else {
                b'.'
            }
        }
        56 => {
            if shift {
                b'?'
            } else {
                b'/'
            }
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const CONFIG: [u8; 34] = [
        9, 2, 34, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 9, 0x21, 0x11, 1, 0, 1, 0x22,
        63, 0, 7, 5, 0x81, 3, 8, 0, 10,
    ];

    fn total(bytes: &mut [u8]) {
        let length = (bytes.len() as u16).to_le_bytes();
        bytes[2..4].copy_from_slice(&length);
    }

    fn report(modifiers: u8, keys: &[u8]) -> [u8; 8] {
        let mut out = [0; 8];
        out[0] = modifiers;
        out[2..2 + keys.len()].copy_from_slice(keys);
        out
    }

    #[test]
    fn selects_boot_interface_and_builds_speed_specific_interval() {
        let selected = select(&CONFIG, SPEED_FULL).unwrap().unwrap();
        assert_eq!(selected.configuration, 1);
        assert_eq!(selected.interface, 0);
        assert_eq!(selected.endpoint.address, 0x81);
        assert_eq!(selected.endpoint.packet, 8);
        assert_eq!(selected.endpoint.dci(), 3);
        assert_eq!(selected.endpoint.interval, 6); // floor(log2(10 * 8))
        assert_eq!(
            select(&CONFIG, SPEED_LOW)
                .unwrap()
                .unwrap()
                .endpoint
                .interval,
            6
        );
        assert_eq!(
            select(&CONFIG, SPEED_HIGH)
                .unwrap()
                .unwrap()
                .endpoint
                .interval,
            9
        );
        assert_eq!(select(&CONFIG, 4), Err(Error::Speed));
    }

    #[test]
    fn rejected_lower_port_configurations_do_not_hide_a_keyboard() {
        let mut oversized = std::vec![0; CONFIG_BYTES + 1];
        oversized[..CONFIG.len()].copy_from_slice(&CONFIG);
        total(&mut oversized);
        let mut attributes = CONFIG.to_vec();
        attributes[7] = 0;
        let mut endpoint = CONFIG.to_vec();
        endpoint[29] = 0x80;
        let mut ambiguous = CONFIG.to_vec();
        ambiguous.extend_from_slice(&CONFIG[9..]);
        ambiguous[4] = 2;
        ambiguous[36] = 1;
        total(&mut ambiguous);
        for rejected in [&oversized, &attributes, &endpoint, &ambiguous] {
            assert!(select(rejected, SPEED_FULL).is_err());
            assert_eq!(supported_configuration(rejected, SPEED_FULL), None);
            let selected = [rejected.as_slice(), CONFIG.as_slice()]
                .into_iter()
                .enumerate()
                .find_map(|(port, bytes)| {
                    supported_configuration(bytes, SPEED_FULL).map(|keyboard| (port, keyboard))
                });
            assert_eq!(
                selected,
                Some((1, select(&CONFIG, SPEED_FULL).unwrap().unwrap()))
            );
        }
    }

    #[test]
    fn reclamation_requires_every_retirement_observation() {
        let clean = Reclaim {
            halted: true,
            bus_master: false,
            reset_complete: true,
            irq_pending: false,
            quiet_unchanged: true,
        };
        assert!(clean.permitted());
        for refused in [
            Reclaim {
                halted: false,
                ..clean
            },
            Reclaim {
                bus_master: true,
                ..clean
            },
            Reclaim {
                reset_complete: false,
                ..clean
            },
            Reclaim {
                irq_pending: true,
                ..clean
            },
            Reclaim {
                quiet_unchanged: false,
                ..clean
            },
        ] {
            assert!(!refused.permitted());
        }
    }

    #[test]
    fn endpoint_context_and_control_setup_have_explicit_wire_fields() {
        let endpoint = select(&CONFIG, SPEED_FULL).unwrap().unwrap().endpoint;
        assert_eq!(
            endpoint.context(0x1_2345_6000),
            [6 << 16, (8 << 16) | 62, 0x2345_6001, 1, (8 << 16) | 8]
        );
        assert_eq!(
            setup(0x21, 0x0b, 0, 3, 0).to_le_bytes(),
            [0x21, 0x0b, 0, 0, 3, 0, 0, 0]
        );
        assert_eq!(
            setup(0xa1, 3, 0, 3, 1).to_le_bytes(),
            [0xa1, 3, 0, 0, 3, 0, 1, 0]
        );
        assert_eq!(setup(0, 9, 2, 0, 0).to_le_bytes(), [0, 9, 2, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn completion_identity_is_independent_of_interrupt_credit() {
        let event = Event::Transfer {
            trb: 0x4000,
            code: 1,
            residual: 0,
            slot: 1,
            endpoint: 3,
            event_data: false,
        };
        assert_eq!(completion(event, 0x4000, 1, 3), Ok(()));
        for (pointer, slot, endpoint) in [
            (0x4010, 1, 3),
            (0x4000, 2, 3),
            (0x4000, 1, 5),
            (0, 1, 3),
            (0x4001, 1, 3),
            (0x4000, 0, 3),
            (0x4000, 1, 2),
        ] {
            assert_eq!(
                completion(event, pointer, slot, endpoint),
                Err(Error::CompletionIdentity)
            );
        }
        for wrong in [
            Event::Transfer {
                event_data: true,
                trb: 0x4000,
                code: 1,
                residual: 0,
                slot: 1,
                endpoint: 3,
            },
            Event::CommandCompletion {
                command: 0x4000,
                code: 1,
                slot: 1,
            },
            Event::PortStatusChange { port: 1 },
        ] {
            assert_eq!(
                completion(wrong, 0x4000, 1, 3),
                Err(Error::CompletionIdentity)
            );
        }
    }

    #[test]
    fn stall_babble_and_short_reports_fail_the_actual_completion_rule() {
        for code in 0..=255 {
            let event = Event::Transfer {
                trb: 0x4000,
                code,
                residual: 0,
                slot: 1,
                endpoint: 3,
                event_data: false,
            };
            assert_eq!(
                completion(event, 0x4000, 1, 3),
                if code == 1 {
                    Ok(())
                } else {
                    Err(Error::CompletionCode(code))
                }
            );
        }
        for residual in [1, 7, 8, 9, 0xff_ffff] {
            let event = Event::Transfer {
                trb: 0x4000,
                code: 1,
                residual,
                slot: 1,
                endpoint: 3,
                event_data: false,
            };
            assert_eq!(
                completion(event, 0x4000, 1, 3),
                Err(Error::CompletionResidual(residual))
            );
        }
    }

    #[test]
    fn every_truncation_and_descriptor_length_is_bounded() {
        for length in 0..CONFIG.len() {
            assert!(select(&CONFIG[..length], SPEED_FULL).is_err());
            if length >= 9 {
                let mut short = CONFIG[..length].to_vec();
                total(&mut short);
                assert!(select(&short, SPEED_FULL).is_err());
            }
        }
        for (at, valid) in [(9, 9), (18, 9), (27, 7)] {
            for length in 0..=255u8 {
                let mut bytes = CONFIG;
                bytes[at] = length;
                let result = select(&bytes, SPEED_FULL);
                assert_eq!(result.is_ok(), length == valid, "at={at} len={length}");
            }
        }
    }

    #[test]
    fn validates_entire_tail_even_after_keyboard() {
        let mut bytes = CONFIG.to_vec();
        bytes.extend_from_slice(&[2, 0xee]);
        total(&mut bytes);
        assert!(select(&bytes, SPEED_FULL).unwrap().is_some());
        bytes.extend_from_slice(&[0, 0xee]);
        total(&mut bytes);
        assert_eq!(select(&bytes, SPEED_FULL), Err(Error::DescriptorLength));
        let mut full = CONFIG.to_vec();
        while full.len() < CONFIG_BYTES {
            full.extend_from_slice(&[2, 0xee]);
        }
        total(&mut full);
        assert!(select(&full, SPEED_FULL).unwrap().is_some());
        full.push(0);
        total(&mut full);
        assert_eq!(select(&full, SPEED_FULL), Err(Error::Configuration));
    }

    #[test]
    fn endpoint_duplicates_are_scoped_to_interface_setting() {
        let mut alternate = CONFIG.to_vec();
        let mut extra = CONFIG[9..].to_vec();
        extra[3] = 1;
        alternate.extend_from_slice(&extra);
        total(&mut alternate);
        assert!(select(&alternate, SPEED_FULL).unwrap().is_some());
        alternate[34 + 3] = 0;
        assert_eq!(select(&alternate, SPEED_FULL), Err(Error::Interface));

        let mut duplicate = CONFIG.to_vec();
        duplicate[13] = 2;
        duplicate.extend_from_slice(&CONFIG[27..]);
        total(&mut duplicate);
        assert_eq!(select(&duplicate, SPEED_FULL), Err(Error::Endpoint));
    }

    #[test]
    fn refuses_ambiguous_interfaces_and_bad_counts() {
        let mut bytes = CONFIG.to_vec();
        bytes[4] = 2;
        let mut extra = CONFIG[9..].to_vec();
        extra[2] = 1;
        bytes.extend_from_slice(&extra);
        total(&mut bytes);
        assert_eq!(select(&bytes, SPEED_FULL), Err(Error::Ambiguous));
        for (offset, value) in [(4, 2), (5, 0), (7, 0), (11, 1), (13, 0), (13, 2)] {
            let mut bytes = CONFIG;
            bytes[offset] = value;
            assert!(
                select(&bytes, SPEED_FULL).is_err(),
                "offset={offset} value={value}"
            );
        }
        let mut mouse = CONFIG;
        mouse[16] = 2;
        assert_eq!(select(&mouse, SPEED_FULL), Ok(None));
    }

    #[test]
    fn requires_a_valid_hid_report_descriptor_reference() {
        for (offset, value) in [(19, 0xee), (23, 0), (23, 2), (24, 0x23), (25, 0)] {
            let mut bytes = CONFIG;
            bytes[offset] = value;
            assert_eq!(select(&bytes, SPEED_FULL), Err(Error::Hid));
        }
    }

    #[test]
    fn endpoint_packet_address_and_interval_boundaries() {
        for speed in [SPEED_LOW, SPEED_FULL, SPEED_HIGH] {
            let max = match speed {
                SPEED_LOW => 8,
                SPEED_FULL => 64,
                _ => 1024,
            };
            for packet in [0, 1, 7, 8, 9, 64, 65, 1024, 1025, 0x0808, u16::MAX] {
                let mut endpoint = CONFIG[27..].to_vec();
                endpoint[4..6].copy_from_slice(&packet.to_le_bytes());
                assert_eq!(
                    Endpoint::parse(&endpoint, speed).is_ok(),
                    (8..=max).contains(&packet)
                );
            }
            for period in 0..=255u8 {
                let mut endpoint = CONFIG[27..].to_vec();
                endpoint[6] = period;
                let parsed = Endpoint::parse(&endpoint, speed);
                assert_eq!(
                    parsed.is_ok(),
                    period != 0
                        && (speed != SPEED_HIGH || period <= 16)
                        && (speed != SPEED_LOW || period >= 10)
                );
                if let Ok(endpoint) = parsed {
                    let microframes = 1u32 << endpoint.interval;
                    let usb_period = if speed == SPEED_HIGH {
                        1 << (period - 1)
                    } else {
                        u32::from(period) * 8
                    };
                    assert!(microframes <= usb_period && microframes * 2 > usb_period);
                }
            }
        }
        for address in 0..=255u8 {
            let mut endpoint = CONFIG[27..].to_vec();
            endpoint[2] = address;
            assert_eq!(
                Endpoint::parse(&endpoint, SPEED_FULL).is_ok(),
                address & 0xf0 == 0x80 && address & 15 != 0
            );
        }
        let mut endpoint = CONFIG[27..].to_vec();
        endpoint[0] = 255;
        assert_eq!(
            Endpoint::parse(&endpoint, SPEED_FULL),
            Err(Error::DescriptorLength)
        );
    }

    #[test]
    fn new_press_set_has_no_repeat_for_hold_reorder_duplicate_or_release() {
        let mut state = Reports::new();
        assert_eq!(state.translate(&report(0, &[4, 5])).unwrap().bytes(), b"ab");
        assert_eq!(
            state.translate(&report(0, &[5, 4, 4])).unwrap().bytes(),
            b""
        );
        assert_eq!(
            state.translate(&report(0x22, &[4, 5])).unwrap().bytes(),
            b""
        );
        assert_eq!(state.translate(&report(0, &[5])).unwrap().bytes(), b"");
        assert_eq!(state.translate(&report(0, &[5, 4])).unwrap().bytes(), b"a");
        assert_eq!(state.translate(&report(0, &[])).unwrap().bytes(), b"");
        assert_eq!(
            state
                .translate(&report(0, &[4, 4, 4, 4, 4, 4]))
                .unwrap()
                .bytes(),
            b"a"
        );
    }

    #[test]
    fn modifiers_caps_and_control_have_local_byte_semantics() {
        let mut state = Reports::new();
        assert_eq!(
            state.translate(&report(2, &[4, 30, 45])).unwrap().bytes(),
            b"A!_"
        );
        state.translate(&report(0, &[])).unwrap();
        assert_eq!(
            state.translate(&report(0, &[4, 0x39])).unwrap().bytes(),
            b"A"
        );
        state.translate(&report(0, &[])).unwrap();
        assert_eq!(state.translate(&report(2, &[4])).unwrap().bytes(), b"a");
        state.translate(&report(0, &[])).unwrap();
        assert_eq!(
            state.translate(&report(1, &[4, 6])).unwrap().bytes(),
            &[1, 3]
        );
        for modifier in [4, 8, 0x40, 0x80] {
            state.translate(&report(0, &[])).unwrap();
            assert_eq!(
                state.translate(&report(modifier, &[4])).unwrap().bytes(),
                b""
            );
            assert_eq!(state.translate(&report(0, &[4])).unwrap().bytes(), b"");
        }
        state.fence();
        assert_eq!(state.translate(&report(0, &[4])).unwrap().bytes(), b"a");
    }

    #[test]
    fn rollover_and_invalid_length_preserve_last_valid_state() {
        let mut state = Reports::new();
        state.translate(&report(0, &[4])).unwrap();
        for error in 1..=3 {
            assert_eq!(
                state.translate(&report(0, &[error; 6])),
                Err(Error::ReportError)
            );
            assert_eq!(state.translate(&report(0, &[4])).unwrap().bytes(), b"");
        }
        for length in 0..=9 {
            if length != 8 {
                assert_eq!(state.translate(&[0; 9][..length]), Err(Error::ReportLength));
            }
        }
        let mut reserved = report(0, &[4]);
        reserved[1] = 0xff;
        assert_eq!(state.translate(&reserved).unwrap().bytes(), b"");
        state.translate(&report(0, &[])).unwrap();
        assert_eq!(state.translate(&report(0, &[4])).unwrap().bytes(), b"a");
        assert_eq!(state.invalid, 12);
    }

    #[test]
    fn fixed_mapping_and_diagnostics_cover_unimplemented_usages() {
        let mut state = Reports::new();
        assert_eq!(
            state
                .translate(&report(0, &[40, 41, 42, 43, 44, 0x70]))
                .unwrap()
                .bytes(),
            &[10, 27, 127, 9, 32]
        );
        assert_eq!(state.unmapped, 1);
        state.invalid = u64::MAX;
        state.unmapped = u64::MAX;
        assert_eq!(state.translate(&[1]), Err(Error::ReportLength));
        state.translate(&report(0, &[])).unwrap();
        assert_eq!(state.translate(&report(0, &[0x70])).unwrap().bytes(), b"");
        assert_eq!(state.invalid, u64::MAX);
        assert_eq!(state.unmapped, u64::MAX);
    }
}
