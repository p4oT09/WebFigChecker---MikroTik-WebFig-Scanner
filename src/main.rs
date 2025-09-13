
use clap::{ArgAction, Parser};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnetwork::Ipv4Network;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// 🚀 WebFigChecker — MikroTik Scanner
/// Founder: Ecbrain
/// Co‑Founder: p4oT09
#[derive(Parser, Debug)]
#[command(name = "webfigchecker",
    about = "Scan IP/CIDR/RANGE/ASN for MikroTik WebFig over HTTP/HTTPS",
    version)]
struct Cli {
    /// Target: IPv4/CIDR (e.g., 144.48.115.0/24), single IP, or IP-IP range (start-end)
    target: Option<String>,

    /// Ports list: "80,443,8080-8090"
    #[arg(long, value_name = "LIST")]
    ports: Option<String>,

    /// Scan all ports 1..=65535
    #[arg(long, action=ArgAction::SetTrue)]
    all_ports: bool,

    /// Concurrency
    #[arg(short='c', long, default_value_t = 400)]
    concurrency: usize,

    /// Timeout per request in milliseconds
    #[arg(long="timeout-ms", default_value_t = 800)]
    timeout_ms: u64,

    /// ASN input file that contains IPv4 prefixes (one per line)
    #[arg(long = "asn-file")]
    asn_file: Option<String>,
}

fn banner() {
    println!(r#"
============================================================
   🚀  WebFigChecker — MikroTik Scanner
       Founder: Ecbrain
       Co‑Founder: p4oT09
============================================================"#);
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    banner();

    let timeout = Duration::from_millis(cli.timeout_ms);

    // Build port set
    let ports: Vec<u16> = if cli.all_ports {
        (1u16..=65535u16).collect()
    } else if let Some(p) = &cli.ports {
        parse_ports(p).unwrap_or_else(|e| {
            eprintln!("Error parsing ports: {e}");
            std::process::exit(1);
        })
    } else {
        vec![80, 8080, 443]
    };

    // Build target IPs
    let mut ips: Vec<Ipv4Addr> = Vec::new();

    if let Some(file) = cli.asn_file.as_ref() {
        match fs::read_to_string(file) {
            Ok(s) => {
                for line in s.lines().map(|x| x.trim()).filter(|x| !x.is_empty()) {
                    if let Ok(net) = line.parse::<Ipv4Network>() {
                        ips.extend(net.iter().collect::<Vec<_>>());
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to read ASN file {}: {e}", file);
                std::process::exit(1);
            }
        }
    }

    if let Some(t) = &cli.target {
        if let Ok(net) = t.parse::<Ipv4Network>() {
            ips.extend(net.iter().collect::<Vec<_>>());
        } else if let Some((start, end)) = parse_range(t) {
            let mut cur = start;
            while cur <= end {
                ips.push(cur);
                if cur == Ipv4Addr::new(255,255,255,255) { break; }
                let n = u32::from(cur).saturating_add(1);
                cur = Ipv4Addr::from(n);
            }
        } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
            ips.push(ip);
        } else {
            eprintln!("Error: invalid IP address syntax");
            std::process::exit(1);
        }
    }

    // Dedup
    let mut set = HashSet::new();
    ips.retain(|ip| set.insert(*ip));

    if ips.is_empty() {
        eprintln!("No targets to scan.");
        return;
    }

    // HTTP client
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("client build");

    let detect_title = Regex::new(r"(?i)mikrotik|webfig").unwrap();

    // Task queue
    let sem = tokio::sync::Semaphore::new(cli.concurrency);
    let mut futs = FuturesUnordered::new();

    for ip in ips {
        for port in &ports {
            let p = *port;
            let ip_s = ip.to_string();
            let client = client.clone();
            let permit = sem.clone().acquire_owned().await.unwrap();
            futs.push(tokio::spawn(async move {
                let _permit = permit;
                let mut schemes = Vec::new();
                // Prefer https on 443, else try http first.
                if p == 443 {
                    schemes = vec!["https", "http"];
                } else {
                    schemes = vec!["http", "https"];
                }
                for scheme in schemes {
                    let url = format!("{scheme}://{ip_s}:{p}/");
                    match client.get(&url).send().await {
                        Ok(resp) => {
                            let server = resp.headers()
                                .get(reqwest::header::SERVER)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            let status = resp.status();
                            let text = resp.text().await.unwrap_or_default();
                            if server.to_ascii_lowercase().contains("mikrotik")
                                || detect_title.is_match(&text)
                            {
                                println!("{ip_s}:{p}  [{status}]  server={server}  url={url}");
                                return;
                            }
                        }
                        Err(_) => {}
                    }
                }
            }));
        }
    }

    while let Some(_res) = futs.next().await {}
}

fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        if let Some((a,b)) = part.split_once('-') {
            let start: u16 = a.parse().map_err(|_| format!("Bad port: {a}"))?;
            let end: u16 = b.parse().map_err(|_| format!("Bad port: {b}"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("Bad range: {part}"));
            }
            for p in start..=end { out.push(p); }
        } else {
            let p: u16 = part.parse().map_err(|_| format!("Bad port: {part}"))?;
            if p == 0 { return Err(format!("Bad port: {p}")); }
            out.push(p);
        }
    }
    if out.is_empty() { return Err("Empty ports list".into()); }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Parse "A.B.C.D-E.F.G.H" IPv4 range
fn parse_range(s: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (a, b) = s.split_once('-')?;
    let start = Ipv4Addr::from_str(a).ok()?;
    let end = Ipv4Addr::from_str(b).ok()?;
    if u32::from(start) <= u32::from(end) { Some((start, end)) } else { None }
}
