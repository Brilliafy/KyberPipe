use clap::{Parser, Subcommand};
use std::io::{self, Read};

#[derive(Parser)]
#[command(name = "kyberpipe")]
#[command(about = "Sovereign P2P Post-Quantum CLI Companion for Kyberpipe Ring", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print active transport path, latency, and mesh nodes status
    Status,

    /// Send instant text payload directly to paired devices
    Send {
        /// Text payload to send
        payload: String,
    },

    /// Stream input directly over QUIC tunnel (supports non-TTY stdin redirection)
    Stream,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Status => {
            // AUDIT FINDING #14: the legacy Status printed FABRICATED telemetry
            // ("Multipath Aggregated", "ML-KEM-768 Active") that the CLI has no
            // way to observe — it is a separate process with no access to the
            // desktop's connection state or ratchet registry. Report honest
            // "not instrumented" values instead of fake metrics that a script
            // or CI could mistake for real telemetry.
            println!("⚡ Kyberpipe Status Indicator");
            println!("Transport path:      NOT INSTRUMENTED — run the desktop app for live connection state");
            println!(
                "Post-Quantum KEM:   NIST ML-KEM-768 + X25519 hybrid (compiled into core-crypto)"
            );
            println!("Average Latency:    NOT INSTRUMENTED — no telemetry source in the CLI");
            println!("Flight Recorder:    NOT INSTRUMENTED — core-crypto recorder is desktop-process state");
        }
        Commands::Send { payload } => {
            // AUDIT FINDING #14: the legacy Send/Stream posted a PLAINTEXT
            // `{"plaintext": ...}` body to STREAM_CLIPBOARD. The desktop only
            // accepts RATCHET-ENCRYPTED binary-TLV payloads (audit finding
            // #12) and correctly rejected those bodies — but the CLI printed
            // "Sent via QUIC" for bytes that never entered a session. The CLI
            // process has NO ratchet session (pairing and the session registry
            // live in the desktop app), so it cannot produce a valid encrypted
            // payload. Fail honestly instead of faking a send.
            eprintln!(
                "SEND REFUSED ({} bytes): the CLI has no ratchet session to encrypt into. \
                 Pair the desktop app first and send from it (or from the phone) \
                 — the desktop only accepts ratchet-encrypted payloads.",
                payload.len()
            );
            std::process::exit(1);
        }
        Commands::Stream => {
            let mut stdin = io::stdin();
            let mut buffer = Vec::new();

            if !is_terminal::is_terminal(&stdin) {
                stdin.read_to_end(&mut buffer)?;
                // Same honest refusal as Send — a plaintext body would be
                // rejected by the desktop (audit finding #14).
                eprintln!(
                    "STREAM REFUSED: the CLI has no ratchet session to encrypt {} bytes into. \
                     Use the desktop app or the Android companion for encrypted transfers.",
                    buffer.len()
                );
                std::process::exit(1);
            } else {
                println!("Error: Non-TTY stdin pipe input required. Example: cat file.txt | kyberpipe stream");
            }
        }
    }

    Ok(())
}

// Inline implementation of is_terminal trait check
mod is_terminal {
    use std::io;
    pub fn is_terminal(_stream: &io::Stdin) -> bool {
        // Direct non-TTY detection checks if stdin is redirected
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            rustix::termios::tcgetattr(io::stdin().as_fd()).is_ok()
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}
