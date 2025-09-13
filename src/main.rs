use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::Ipv4Net;
use reqwest::Client;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "WebFigChecker — MikroTik WebFig Scanner",
    version,
    about = "Fast Rust scanner to detect MikroTik WebFig across IPs / CIDRs / Ranges",
)]
struct Args {
    /// Single IP, CIDR, or Range (examples: 1.2.3.4 | 1.2.3.0/24 | 1.2.3.4-1.2.3.254)
    ip: String,

    /// Comma separated ports (default: 80,443,8080,8291,8443)
    #[arg(long, value_parser = parse_ports)]
    ports: Option<Vec<u16>>,

    /// Scan all 1..=65535 ports
    #[arg(long = "all-ports", default_value_t = false)]
    all_ports: bool,

    /// Concurrency (parallel workers)
    #[arg(short = 'c', long, default_value_t = 400)]
    concurrency: usize,

    /// Request timeout in milliseconds
    #[arg(long = "timeout-ms", default_value_t = 800)]
    timeout_ms: u64,
}

fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    s.split(',')
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", p))
        })
        .collect()
}

fn banner() {
    println!(
        r#"
====================================================
🚀  WebFigChecker – MikroTik Scanner 🚀
Founder: Ecbrain
Co-Founder: p4oT09
====================================================
"#);
}

fn expand_ips(input: &str) -> Result<Vec<IpAddr>, String> {
    // CIDR: 1.2.3.0/24
    if input.contains('/') {
        let net = Ipv4Net::from_str(input).map_err(|_| "Invalid CIDR".to_string())?;
        let mut ips = Vec::new();
        for ip in net.hosts() {
            ips.push(IpAddr::V4(ip));
        }
        return Ok(ips);
    }

    // Range: 1.2.3.4-1.2.3.254
    if input.contains('-') {
        let mut parts = input.split('-');
        let a = parts
            .next()
            .ok_or("Invalid range")?
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| "Invalid range start".to_string())?;
        let b = parts
            .next()
            .ok_or("Invalid range")?
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| "Invalid range end".to_string())?;

        let (start, end) = (u32::from(a), u32::from(b));
        if start > end {
            return Err("Range start > end".into());
        }
        let mut ips = Vec::with_capacity((end - start + 1) as usize);
        for v in start..=end {
            ips.push(IpAddr::V4(Ipv4Addr::from(v)));
        }
        return Ok(ips);
    }

    // Single IP
    let ip = IpAddr::from_str(input).map_err(|_| "Invalid IP address syntax".to_string())?;
    Ok(vec![ip])
}

fn default_webfig_ports() -> Vec<u16> {
    vec![80, 443, 8080, 8291, 8443]
}

fn is_https_port(p: u16) -> bool {
    matches!(p, 443 | 8443)
}

async fn check_one(client: &Client, ip: &IpAddr, port: u16, timeout: Duration) -> Option<String> {
    let scheme = if is_https_port(port) { "https" } else { "http" };
    let url = format!("{scheme}://{ip}:{port}/");

    let resp = client.get(&url).timeout(timeout).send().await.ok()?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    // Simple WebFig heuristics
    let looks_like_webfig = body.contains("WebFig")
        || body.contains("MikroTik")
        || headers
            .get("Server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("MikroTik"))
            .unwrap_or(false)
        || status.is_success() && body.to_lowercase().contains("routeros");

    if looks_like_webfig {
        Some(format!("{ip}:{port} -> webfig"))
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    banner();

    let args = Args::parse();

    let ips = match expand_ips(&args.ip) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(2);
        }
    };

    let ports: Vec<u16> = if args.all_ports {
        (1u16..=65535u16).collect()
    } else {
        args.ports.unwrap_or_else(default_webfig_ports)
    };

    println!(
        "Targets: {} | Ports: {} | concurrency={} | timeout={}ms",
        ips.len(),
        ports.len(),
        args.concurrency,
        args.timeout_ms
    );

    let timeout = Duration::from_millis(args.timeout_ms);
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let sem = Semaphore::new(args.concurrency);
    let mut futs = FuturesUnordered::new();

    for ip in ips {
        for &port in &ports {
            let permit = sem.clone().acquire_owned().await?;
            let c = client.clone();
            futs.push(tokio::spawn(async move {
                let _p = permit; // keep permit alive
                let out = check_one(&c, &ip, port, timeout).await;
                out
            }));
        }
    }

    while let Some(res) = futs.next().await {
        if let Ok(Some(line)) = res {
            println!("{line}");
        }
    }

    Ok(())
}