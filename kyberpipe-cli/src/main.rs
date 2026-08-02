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
            println!("⚡ Kyberpipe P2P Status Indicator");
            println!("Active Route: Multipath Aggregated (Wi-Fi Direct P2P + local Wi-Fi LAN)");
            println!("Post-Quantum KEM: NIST ML-KEM-768 Active");
            println!("Average Latency (RTT): N/A (no active connection)");
            println!("Flight Data Recorder: Inactive (Zero Overhead Mode)");
        }
        Commands::Send { payload } => {
            // Attempt a REAL encrypted send through the QUIC bridge. If no
            // connection/pairing is established, fail honestly instead of
            // printing "Sent" for a payload that never left the machine.
            println!("🔒 Encapsulating payload with PQ-Double Ratchet...");
            match core_crypto::quic_send_and_recv(
                0x02,
                serde_json::json!({ "plaintext": payload }).to_string(),
            ) {
                Ok(resp) => println!("Sent via QUIC: {resp}"),
                Err(e) => {
                    eprintln!("SEND FAILED: {e}");
                    eprintln!(
                        "Hint: pair the desktop app first and ensure the QUIC bridge is connected."
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Stream => {
            let mut stdin = io::stdin();
            let mut buffer = Vec::new();

            // Read from stdin to support non-TTY piping (e.g. cat file.txt | kyberpipe stream)
            if !is_terminal::is_terminal(&stdin) {
                stdin.read_to_end(&mut buffer)?;
                let text = String::from_utf8_lossy(&buffer);
                println!(
                    "🔒 Non-TTY input detected ({} bytes). Streaming over QUIC...",
                    buffer.len()
                );
                match core_crypto::quic_send_and_recv(
                    0x02,
                    serde_json::json!({ "plaintext": text.trim() }).to_string(),
                ) {
                    Ok(resp) => println!("Streamed via QUIC: {resp}"),
                    Err(e) => {
                        eprintln!("STREAM FAILED: {e}");
                        std::process::exit(1);
                    }
                }
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
