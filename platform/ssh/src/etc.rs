//! The two configuration files sshd reads at start, through the file
//! server's control channel (which sees `/etc` read-only):
//!
//! - `/etc/network.conf` (network.conf(5)): `address`, `netmask`, and
//!   optionally `gateway`, each a dotted IPv4 address.
//! - `/etc/sshd.conf` (sshd.conf(5)): `port`, `max-connections`,
//!   `login-grace-time`, `idle-timeout`, `max-auth-tries`, each a decimal
//!   number.
//!
//! Format, both files: one `keyword value` per line, words separated by
//! spaces or tabs; blank lines and lines whose first non-blank character
//! is `#` are ignored; a keyword appears at most once. Anything else (an
//! unknown keyword, a missing or extra word, a value out of range, a
//! duplicate, a byte outside printable ASCII, more than [`MAX_BYTES`]) is
//! refused with the line number, and sshd does not start: an error in a
//! file the operator wrote is never replaced by a default silently. A
//! missing file means the built-in defaults, and sshd says which it used.

use std::time::Duration;

/// Largest configuration file accepted.
pub const MAX_BYTES: usize = 4096;

pub const NETWORK_PATH: &str = "/etc/network.conf";
pub const SSHD_PATH: &str = "/etc/sshd.conf";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub address: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
}

impl Network {
    /// QEMU's user network (`-netdev user`): 10.0.2.15/24 via 10.0.2.2.
    pub const DEFAULT: Network = Network { address: [10, 0, 2, 15], prefix_len: 24, gateway: Some([10, 0, 2, 2]) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sshd {
    pub port: u16,
    pub max_connections: usize,
    pub login_grace: Duration,
    pub idle_timeout: Duration,
    pub max_auth_tries: u32,
}

impl Sshd {
    pub const DEFAULT: Sshd = Sshd {
        port: 22,
        max_connections: 4,
        login_grace: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(1800),
        max_auth_tries: 6,
    };
}

/// `(line number, keyword, value)` for every setting line, or the first
/// line that is not one.
fn lines<'t>(text: &'t [u8], known: &[&str]) -> Result<Vec<(usize, &'t str, &'t str)>, String> {
    if text.len() > MAX_BYTES {
        return Err(format!("larger than {MAX_BYTES} bytes"));
    }
    if let Some(at) = text.iter().position(|&b| !(0x20..0x7f).contains(&b) && b != b'\t' && b != b'\n') {
        let line = text[..at].iter().filter(|&&b| b == b'\n').count() + 1;
        return Err(format!("line {line}: byte 0x{:02x} is not printable ASCII", text[at]));
    }
    let text = std::str::from_utf8(text).expect("checked ASCII");
    let mut out: Vec<(usize, &str, &str)> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let words: Vec<&str> = raw.split([' ', '\t']).filter(|w| !w.is_empty()).collect();
        match words.as_slice() {
            [] => {}
            [first, ..] if first.starts_with('#') => {}
            [keyword, value] => {
                if !known.contains(keyword) {
                    return Err(format!("line {number}: unknown keyword \"{keyword}\" (known: {})", known.join(", ")));
                }
                if let Some((earlier, ..)) = out.iter().find(|(_, k, _)| k == keyword) {
                    return Err(format!("line {number}: \"{keyword}\" already set on line {earlier}"));
                }
                out.push((number, keyword, value));
            }
            [keyword] => return Err(format!("line {number}: \"{keyword}\" needs a value")),
            [keyword, ..] => return Err(format!("line {number}: \"{keyword}\" takes one value")),
        }
    }
    Ok(out)
}

fn ipv4(number: usize, keyword: &str, value: &str) -> Result<[u8; 4], String> {
    let bad = || format!("line {number}: {keyword} \"{value}\" is not a dotted IPv4 address");
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return Err(bad());
    }
    let mut out = [0u8; 4];
    for (slot, part) in out.iter_mut().zip(parts) {
        // Decimal only, no leading zeros (no octal reading of "010").
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) || (part.len() > 1 && part.starts_with('0')) {
            return Err(bad());
        }
        *slot = part.parse().map_err(|_| bad())?;
    }
    Ok(out)
}

pub fn parse_network(text: &[u8]) -> Result<Network, String> {
    let mut address = None;
    let mut netmask = None;
    let mut gateway = None;
    for (number, keyword, value) in lines(text, &["address", "netmask", "gateway"])? {
        let ip = ipv4(number, keyword, value)?;
        match keyword {
            "address" => address = Some((number, ip)),
            "netmask" => {
                let bits = u32::from_be_bytes(ip);
                if bits.leading_ones() + bits.trailing_zeros() != 32 || !(1..=30).contains(&bits.leading_ones()) {
                    return Err(format!("line {number}: netmask {value} is not a contiguous mask of 1 to 30 bits"));
                }
                netmask = Some(bits.leading_ones() as u8);
            }
            _ => gateway = Some((number, ip)),
        }
    }
    let (number, address) = address.ok_or("no \"address\" line")?;
    let prefix_len = netmask.ok_or("no \"netmask\" line")?;
    let mask = u32::MAX << (32 - prefix_len);
    let host = u32::from_be_bytes(address);
    let net = host & mask;
    if host & !mask == 0 || host & !mask == !mask || address[0] == 0 || address[0] == 127 || address[0] >= 224 {
        return Err(format!(
            "line {number}: address {} is not a usable host address of its /{prefix_len} network",
            dotted(address)
        ));
    }
    if let Some((number, gw)) = gateway {
        let g = u32::from_be_bytes(gw);
        if g & mask != net || g == host || g & !mask == 0 || g & !mask == !mask {
            return Err(format!(
                "line {number}: gateway {} is not another host of {}/{prefix_len}",
                dotted(gw),
                dotted(address)
            ));
        }
    }
    Ok(Network { address, prefix_len, gateway: gateway.map(|(_, gw)| gw) })
}

pub fn dotted(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn number(line: usize, keyword: &str, value: &str, low: u64, high: u64) -> Result<u64, String> {
    let bad = || format!("line {line}: {keyword} \"{value}\" is not a whole number from {low} to {high}");
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || value.len() > 10 {
        return Err(bad());
    }
    let n: u64 = value.parse().map_err(|_| bad())?;
    if !(low..=high).contains(&n) {
        return Err(bad());
    }
    Ok(n)
}

/// The most `max-connections` admits: what the kernel's tables serve.
pub const MAX_CONNECTIONS: u64 = 4;

pub fn parse_sshd(text: &[u8]) -> Result<Sshd, String> {
    let mut out = Sshd::DEFAULT;
    let known = ["port", "max-connections", "login-grace-time", "idle-timeout", "max-auth-tries"];
    for (line, keyword, value) in lines(text, &known)? {
        match keyword {
            "port" => out.port = number(line, keyword, value, 1, 65_535)? as u16,
            // What the tables serve (measured by scripts/contain-matrix.py
            // --only capacity): 48 kernel pipes, 24 taken by the file
            // server's channels and sshd's own streams, 5 per shell session
            // without a terminal (3 streams, 2 control); a fifth such shell
            // is refused its control channel (-12). Every session also
            // keeps a file server slot and a spare in reserve for the others.
            "max-connections" => out.max_connections = number(line, keyword, value, 1, MAX_CONNECTIONS)? as usize,
            "login-grace-time" => out.login_grace = Duration::from_secs(number(line, keyword, value, 1, 3600)?),
            "idle-timeout" => out.idle_timeout = Duration::from_secs(number(line, keyword, value, 1, 604_800)?),
            _ => out.max_auth_tries = number(line, keyword, value, 1, 100)? as u32,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_files_are_read_exactly() {
        let good = b"# lab bridge\naddress 192.168.7.20\n\tnetmask\t255.255.255.0 \n\ngateway 192.168.7.1\n";
        assert_eq!(
            parse_network(good),
            Ok(Network { address: [192, 168, 7, 20], prefix_len: 24, gateway: Some([192, 168, 7, 1]) })
        );
        assert_eq!(
            parse_network(b"address 10.0.2.20\nnetmask 255.255.0.0\n"),
            Ok(Network { address: [10, 0, 2, 20], prefix_len: 16, gateway: None })
        );
        let refused = |text: &[u8], want: &str| {
            let error = parse_network(text).unwrap_err();
            assert!(error.contains(want), "{text:?}: {error}");
        };
        refused(b"netmask 255.255.255.0\n", "no \"address\" line");
        refused(b"address 10.0.2.20\n", "no \"netmask\" line");
        refused(b"address 10.0.2.20\nnetmask 255.255.255.0\nhostname x\n", "line 3: unknown keyword \"hostname\"");
        refused(b"address 10.0.2.20\naddress 10.0.2.21\n", "line 2: \"address\" already set on line 1");
        refused(b"address 10.0.2\nnetmask 255.255.255.0\n", "line 1: address \"10.0.2\" is not a dotted IPv4");
        refused(b"address 10.0.2.020\nnetmask 255.255.255.0\n", "not a dotted IPv4");
        refused(b"address 10.0.2.256\nnetmask 255.255.255.0\n", "not a dotted IPv4");
        refused(b"address 10.0.2.20 extra\n", "line 1: \"address\" takes one value");
        refused(b"address\n", "line 1: \"address\" needs a value");
        refused(b"address 10.0.2.20\nnetmask 255.0.255.0\n", "line 2: netmask 255.0.255.0 is not a contiguous");
        refused(b"address 10.0.2.20\nnetmask 255.255.255.255\n", "not a contiguous mask of 1 to 30 bits");
        refused(b"address 10.0.2.0\nnetmask 255.255.255.0\n", "line 1: address 10.0.2.0 is not a usable host");
        refused(b"address 10.0.2.255\nnetmask 255.255.255.0\n", "is not a usable host");
        refused(b"address 127.0.0.2\nnetmask 255.0.0.0\n", "is not a usable host");
        refused(b"address 10.0.2.20\nnetmask 255.255.255.0\ngateway 10.0.3.1\n", "line 3: gateway 10.0.3.1 is not another host");
        refused(b"address 10.0.2.20\nnetmask 255.255.255.0\ngateway 10.0.2.20\n", "is not another host");
        refused(b"address 10.0.2.20\r\nnetmask 255.255.255.0\n", "line 1: byte 0x0d is not printable ASCII");
        refused(&[b'#'; MAX_BYTES + 1], "larger than 4096 bytes");
    }

    #[test]
    fn sshd_files_are_read_exactly() {
        assert_eq!(parse_sshd(b""), Ok(Sshd::DEFAULT));
        assert_eq!(parse_sshd(b"# nothing set\n\n"), Ok(Sshd::DEFAULT));
        let set = parse_sshd(b"port 2200\nmax-connections 2\nlogin-grace-time 10\nidle-timeout 60\nmax-auth-tries 3\n");
        assert_eq!(
            set,
            Ok(Sshd {
                port: 2200,
                max_connections: 2,
                login_grace: Duration::from_secs(10),
                idle_timeout: Duration::from_secs(60),
                max_auth_tries: 3,
            })
        );
        let refused = |text: &[u8], want: &str| {
            let error = parse_sshd(text).unwrap_err();
            assert!(error.contains(want), "{text:?}: {error}");
        };
        refused(b"Port 22\n", "line 1: unknown keyword \"Port\"");
        refused(b"port 0\n", "line 1: port \"0\" is not a whole number from 1 to 65535");
        refused(b"port 65536\n", "from 1 to 65535");
        refused(b"port 22s\n", "is not a whole number");
        refused(b"port -1\n", "is not a whole number");
        refused(b"max-connections 5\n", "max-connections \"5\" is not a whole number from 1 to 4");
        refused(b"idle-timeout 0\n", "from 1 to 604800");
        refused(b"port 22\nport 23\n", "line 2: \"port\" already set on line 1");
        refused(b"port 22 # ssh\n", "\"port\" takes one value");
        refused(b"port 22\n\x7f\n", "line 2: byte 0x7f");
    }
}
