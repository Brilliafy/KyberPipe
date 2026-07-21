use std::io::{self, Read, Write};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct NativeBrowserMessage {
    pub message_type: String,
    pub content: String,
    pub timestamp: u64,
}

/// WebExtension Native Messaging Host stdin/stdout binary protocol runner
#[allow(dead_code)]
pub fn run_native_messaging_loop() -> io::Result<()> {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        let mut length_bytes = [0u8; 4];
        if stdin.read_exact(&mut length_bytes).is_err() {
            break; // Connection closed by browser
        }

        let length = u32::from_ne_bytes(length_bytes) as usize;
        let mut msg_buffer = vec![0u8; length];
        stdin.read_exact(&mut msg_buffer)?;

        if let Ok(msg) = serde_json::from_slice::<NativeBrowserMessage>(&msg_buffer) {
            eprintln!("[Native Browser Bridge] Received web snippet: {} ({})", msg.message_type, msg.content.len());

            let response = NativeBrowserMessage {
                message_type: "ACK".to_string(),
                content: "Payload routed to Kyberpipe P2P Pipe".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };

            let resp_bytes = serde_json::to_vec(&response)?;
            let resp_len = (resp_bytes.len() as u32).to_ne_bytes();
            stdout.write_all(&resp_len)?;
            stdout.write_all(&resp_bytes)?;
            stdout.flush()?;
        }
    }

    Ok(())
}
