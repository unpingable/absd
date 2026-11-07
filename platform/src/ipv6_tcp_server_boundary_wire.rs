//! Private native fixture literals; no endpoint or library behavior.
fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("boundary literal hex"))
        .collect()
}
pub fn cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    include_str!("../fixtures/native-ipv6-tcp-server/boundary-v3.txt")
        .lines()
        .map(|line| {
            let (name, wire) = line.split_once('=').expect("boundary name");
            let (request, reply) = wire.split_once(':').expect("boundary reply");
            (name, decode(request), decode(reply))
        })
        .collect()
}
