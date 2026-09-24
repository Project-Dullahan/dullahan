use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: obsidian_ping <host:port> (e.g., google.com:80)");
        std::process::exit(1);
    }

    let target = &args[1];
    println!("[DULLAHAN] Initiating TCP latency probe...");
    println!("Target: {}\n", target);

    let resolved_target = if !target.contains(':') {
        format!("{}:80", target)
    } else {
        target.to_string()
    };

    let socket_addr = match resolved_target.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                eprintln!("Error: Hostname resolved to empty address list.");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error: DNS resolution failed. ({})", e);
            std::process::exit(1);
        }
    };

    for sequence in 1..=4 {
        let start_time = Instant::now();
        let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3));
        let duration = start_time.elapsed();
        
        match stream {
            Ok(_) => {
                let ms = duration.as_millis();
                let status = if ms < 50 {
                    "Normal"
                } else if ms < 150 {
                    "Elevated Latency"
                } else {
                    "Severe Degradation"
                };
                println!("  [Seq {}] {} ms - {}", sequence, ms, status);
            }
            Err(e) => {
                println!("  [Seq {}] Connection Timeout/Refused (Host unreachable or actively blocking). Detail: {}", sequence, e);
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("\n[INFO] TCP probe complete.");
}
