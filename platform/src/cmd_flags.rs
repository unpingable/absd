#![allow(dead_code)]
//! Shared by the /bin commands: leading `-x` words are options, `--` ends
//! them, and an option the command does not have is a usage error (status
//! 2) rather than a path. A file whose name starts with `-` is reached as
//! `./-name` or after `--`; `-` alone is never an option.

/// Removes the leading options from `args` and returns them. Exits with
/// status 2 on an option not in `known`.
pub fn take(name: &str, args: &mut Vec<String>, known: &[&str]) -> Vec<String> {
    let mut taken = Vec::new();
    while let Some(first) = args.first() {
        if first == "--" {
            args.remove(0);
            break;
        }
        if !first.starts_with('-') || first == "-" {
            break;
        }
        if !known.contains(&first.as_str()) {
            let only = if known.is_empty() {
                format!("{name} takes no options")
            } else {
                format!("only {}", known.join(", "))
            };
            eprintln!("{name}: unknown option {first} ({only})");
            std::process::exit(2);
        }
        taken.push(args.remove(0));
    }
    taken
}
