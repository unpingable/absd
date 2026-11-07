//! Local enrollment uses a random 128-bit token, never a human password.
//! Only its SHA-256 verifier is installed, under /ssh (excluded from sessions).
use sha2::{Digest, Sha256};
#[derive(Clone)]
pub struct Verifier([u8; 32]);
impl Verifier {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let hex = text
            .strip_prefix("ABSD-LOCAL-1 operator ")?
            .strip_suffix('\n')?;
        if hex.len() != 64 {
            return None;
        }
        let mut digest = [0; 32];
        for (at, part) in hex.as_bytes().chunks_exact(2).enumerate() {
            let value = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            digest[at] = value(part[0])? * 16 + value(part[1])?;
        }
        Some(Self(digest))
    }
    pub fn verify(&self, token: &[u8]) -> bool {
        if token.len() != 32
            || !token
                .iter()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return false;
        }
        let actual = Sha256::digest(token);
        self.0
            .iter()
            .zip(actual.iter())
            .fold(0u8, |d, (a, b)| d | a ^ b)
            == 0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrolled_random_token_only() {
        let token = b"000102030405060708090a0b0c0d0e0f";
        let digest = Sha256::digest(token)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let v = Verifier::parse(format!("ABSD-LOCAL-1 operator {digest}\n").as_bytes()).unwrap();
        assert!(v.verify(token));
        assert!(!v.verify(b"password"));
        assert!(!v.verify(b"000102030405060708090a0b0c0d0e0e"));
        assert!(Verifier::parse(b"ABSD-LOCAL-1 operator xyz\n").is_none());
        assert!(
            Verifier::parse(format!("ABSD-LOCAL-1 operator {digest}\nextra").as_bytes()).is_none()
        );
    }
}
