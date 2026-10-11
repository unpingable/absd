#![feature(restricted_std)]

use std::collections::BTreeMap;
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    absd_runtime::link_anchor();

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let mut counts = BTreeMap::<String, usize>::new();
    for word in input.split_whitespace() {
        *counts.entry(word.to_lowercase()).or_default() += 1;
    }

    let mut output = format!(
        "bytes={} lines={} words={} unique={}\n",
        input.len(),
        input.lines().count(),
        counts.values().sum::<usize>(),
        counts.len(),
    );
    for (word, count) in counts {
        output.push_str(&format!("{word}={count}\n"));
    }
    output.push_str("ABSD RUST TEXT STATS OK\n");
    std::io::stdout().write_all(output.as_bytes())?;
    Ok(())
}
