//! The veilroom binary: runs the interactive application supervisor.

use std::process::ExitCode;

/// The runtime entry point.
#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => veilroom::app::run().await,
        [flag, path] if flag == "--tor-binary" => {
            veilroom::app::run_with_tor_binary(Some(path.into())).await
        }
        [argument] if argument.starts_with("--tor-binary=") => {
            let path = argument.trim_start_matches("--tor-binary=");
            if path.is_empty() {
                eprintln!("veilroom: --tor-binary requires a path");
                ExitCode::FAILURE
            } else {
                veilroom::app::run_with_tor_binary(Some(path.into())).await
            }
        }
        [flag] if flag == "--version" || flag == "-V" => {
            println!("veilroom {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "veilroom - terminal-based ephemeral group chat over Tor\n\n\
                 USAGE:\n    veilroom [OPTIONS]\n\n\
                 OPTIONS:\n    --tor-binary PATH  Use this Tor executable\n    -h, --help         Print help\n    -V, --version      Print version\n\n\
                 The interactive terminal UI starts when no option is given."
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("veilroom: unknown arguments; use --help for usage");
            ExitCode::FAILURE
        }
    }
}
