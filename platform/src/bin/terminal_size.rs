#![feature(restricted_std)]
//! Read live terminal observations without guessing a default geometry.
fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let watch = match args.as_slice() {
        [] => false,
        [arg] if arg == "--watch" => true,
        _ => { eprintln!("usage: terminal-size [--watch]"); std::process::exit(2); }
    };
    let mut previous = None;
    loop {
        let size = absd_runtime::terminal::size().filter(|s| s.columns != 0 && s.rows != 0);
        if size != previous || previous.is_none() {
            match size {
                Some(size) => println!("{} {}", size.rows, size.columns),
                None => {
                    eprintln!("terminal-size: terminal dimensions unknown");
                    std::process::exit(1);
                }
            }
            previous = size;
        }
        if !watch { return; }
        absd_runtime::sleep_ticks(100);
    }
}
