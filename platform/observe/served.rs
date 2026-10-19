#![cfg_attr(target_os = "absd", feature(restricted_std))]

//! Pulse's existing ABSD frame-pressure family as an ordinary FSD client.
//! This entry point acquires no block device and adds no observation schema.

use std::io::{Read as _, Write as _};
use std::path::Path;

use pulse_absd_frame_pressure::{
    LoadSupportConfigV1, PresentEvidenceQueryV1, ingest, produce, resolve,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("pulse-frame-pressure: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    #[cfg(target_os = "absd")]
    {
        absd_runtime::link_anchor();
        if !absd_runtime::fsd::active() {
            return Err("an existing FSD session is required; this command has no direct-block fallback".into());
        }
    }
    #[cfg(not(target_os = "absd"))]
    return Err("this command requires a native ABSD FSD session".into());

    #[cfg(target_os = "absd")]
    run_args(&std::env::args().skip(1).collect::<Vec<_>>())
}

fn configuration(path: &str) -> Result<LoadSupportConfigV1, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("configuration path must be absolute".into());
    }
    LoadSupportConfigV1::from_path(path)
}

fn run_args(args: &[String]) -> Result<(), String> {
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["cycle", "--config", path, "--acquisition-id", acquisition] => {
            let config = configuration(path)?;
            let evidence = produce(&config, acquisition)?;
            println!("PULSE FRAME PRESSURE PRODUCED evidence_id={evidence}");
            let receipt = ingest(&config, acquisition)?;
            println!("PULSE FRAME PRESSURE RECEIVED receipt_id={receipt}");
            Ok(())
        }
        ["resolve", "--config", path] => {
            let config = configuration(path)?;
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > 64 * 1024 {
                return Err("Nightshift support query exceeds the byte bound".into());
            }
            let query: PresentEvidenceQueryV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            let support = resolve(&config, &query)?;
            std::io::stdout()
                .write_all(&serde_jcs::to_vec(&support).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())
        }
        _ => Err("usage: pulse-frame-pressure cycle --config ABSOLUTE_PATH --acquisition-id TOKEN | resolve --config ABSOLUTE_PATH".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_ambiguous_or_expanded_arguments() {
        for args in [
            vec![],
            vec!["cycle"],
            vec!["resolve", "--config", "/x", "extra"],
            vec!["cycle", "--config", "/x", "--acquisition-id", "a", "extra"],
            vec!["produce", "--config", "/x", "--acquisition-id", "a"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(run_args(&args).unwrap_err().starts_with("usage:"));
        }
    }

    #[test]
    fn refuses_relative_or_missing_configuration() {
        assert_eq!(
            configuration("relative").unwrap_err(),
            "configuration path must be absolute"
        );
        assert!(configuration("/absd-u2-fixture-no-such-configuration").is_err());
    }
}
