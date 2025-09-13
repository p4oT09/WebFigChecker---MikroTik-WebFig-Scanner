
use clap::{ArgAction, Parser};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnetwork::{IpNetwork, Ipv4Network};
use regex::Regex;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

fn banner() {
    println!();
    println!("============================================================");
    println!("🚀  WebFigChecker – MikroTik Scanner");
    println!("Founder: Ecbrain");
    println!("Co-Founder: p4oT09");
    println!("============================================================");
    println!();
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "webfigchecker",
    version,
    about = "Fast WebFig (MikroTik) scanner over HTTP/HTTPS with IP, CIDR, Range, and ASN support"
)]
struct Cli {
    /// Target: single IP (1.2.3.4), CIDR (1.2.3.0/24), or range (1.2.3.4-1.2.3.200)
    target: Option<String>,

    /// Scan by ASN, e.g. AS13335 or 13335 (uses bgpview)
    #[arg(long = "asn")]
    asn: Option<String>,

    /// Scan all ports 1..=65535
    #[arg(long = "all-ports", action=ArgAction::SetTrue)]
    all_ports: bool,

    /// Comma-separated list of ports, ex: 80,443,8080-8090
    #[arg(long = "ports")]
    ports: Option<String>,

    /// Concurrency (parallel sockets)
    #[arg(short='c', long, default_value_t = 400)]
    concurrency: usize,

    /// Timeout per connect/request in ms
    #[arg(long = "timeout-ms", default_value_t = 800)]
    timeout_ms: u64,
}

// ---- Port parsing ----
fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        if let Some((a,b)) = part.split_once('-') {
            let start: u16 = a.parse().map_err(|_| format!("Bad port: {a}"))?;
            let end: u16 = b.parse().map_err(|_| format!("Bad port: {b}"))?;
            if start == 0 || end == 0 || start > end { return Err(format!("Bad range: {part}")); }
            out.extend(start..=end);
        } else {
            let p: u16 = part.parse().map_err(|_| format!("Bad port: {part}"))?;
            if p == 0 { return Err(format!("Bad port: {p}")); }
            out.push(p);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn default_ports() -> Vec<u16> { vec![80,443,8080,81,82,83,8000,8888,8291] }

// ---- Target expansion ----
fn expand_cidr(net: Ipv4Network) -> Vec<Ipv4Addr> {
    net.iter().collect()
}

fn expand_range(s: &str) -> Option<Vec<Ipv4Addr>> {
    let (a,b) = s.split_once('-')?;
    let start: Ipv4Addr = a.trim().parse().ok()?;
    let end: Ipv4Addr = b.trim().parse().ok()?;
    if u32::from(start) > u32::from(end) { return None; }
    let mut v = Vec::with_capacity((u32::from(end) - u32::from(start) + 1) as usize);
    let mut cur = u32::from(start);
    let end_u = u32::from(end);
    while cur <= end_u {
        v.push(Ipv4Addr::from(cur));
        cur = cur.saturating_add(1);
    }
    Some(v)
}

#[derive(Debug, Deserialize)]
struct BgpViewPrefixes {
    data: Option<BgpViewData>
}
#[derive(Debug, Deserialize)]
struct BgpViewData {
    #[serde(default)]
    ipv4_prefixes: Vec<BgpViewPrefix>,
}
#[derive(Debug, Deserialize)]
struct BgpViewPrefix { prefix: String }

async fn expand_asn(asn_str: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut asn = asn_str.trim().to_uppercase();
    if let Some(s) = asn.strip_prefix("AS") { asn = s.to_string(); }
    let _ = asn.parse::<u64>()?; // validate numeric

    let url = format!("https://api.bgpview.io/asn/{}/prefixes", asn);
    let resp = reqwest::Client::new().get(&url).send().await?;
    let parsed: BgpViewPrefixes = resp.json().await?;
    let mut out = Vec::new();
    if let Some(data) = parsed.data {
        for p in data.ipv4_prefixes {
            if let Ok(IpNetwork::V4(v4)) = p.prefix.parse::<IpNetwork>() {
                // Add all hosts in each prefix (careful for very large CIDRs)
                out.extend(v4.iter());
            }
        }
    }
    // de-dup
    out.sort_unstable_by_key(|ip| u32::from(*ip));
    out.dedup();
    Ok(out)
}

async fn expand_targets(cli: &Cli) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();

    if let Some(asn) = &cli.asn {
        let mut v = expand_asn(asn).await?;
        ips.append(&mut v);
    }

    if let Some(t) = &cli.target {
        if let Ok(IpNetwork::V4(net)) = t.parse::<IpNetwork>() {
            ips.extend(expand_cidr(net));
        } else if let Some(v) = expand_range(t) {
            ips.extend(v);
        } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
            ips.push(ip);
        } else {
            anyhow::bail!("invalid target: {}", t);
        }
    }

    if ips.is_empty() {
        anyhow::bail!("no targets provided. Give --asn or <target>");
    }

    // de-dup
    ips.sort_unstable_by_key(|ip| u32::from(*ip));
    ips.dedup();
    Ok(ips)
}

// ---- Probing ----
fn is_https_port(p: u16) -> bool { matches!(p, 443|8443) }

async fn probe_http(client: &reqwest::Client, url: &str, timeout_ms: u64) -> Option<(u16, String)> {
    let resp = timeout(Duration::from_millis(timeout_ms), client.get(url).send()).await.ok()??;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    let mut tag = String::new();
    let lower = body.to_ascii_lowercase();
    if lower.contains("webfig") || lower.contains("mikrotik") || lower.contains("routeros") {
        tag = "webfig".into();
    } else if status.is_success() {
        tag = "http".into();
    }
    let server = headers
        .get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tag = if tag == "webfig" { format!("webfig (server={})", server) } else { tag };
    Some((status.as_u16(), tag))
}

async fn probe_one(ip: Ipv4Addr, port: u16, client: &reqwest::Client, timeout_ms: u64) -> Option<String> {
    // try HTTP then HTTPS (or reverse if HTTPS-ish port)
    let schemes = if is_https_port(port) { ["https", "http"] } else { ["http", "https"] };
    for sch in schemes {
        let url = format!("{sch}://{}:{}/", ip, port);
        if let Some((code, tag)) = probe_http(client, &url, timeout_ms).await {
            if !tag.is_empty() {
                return Some(format!("{}:{} -> {} [{}] {}", ip, port, tag, code, url));
            } else {
                return Some(format!("{}:{} -> open [{}] {}", ip, port, code, url));
            }
        }
    }
    // As a fallback, plain TCP connect check:
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    if timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await.ok().flatten().is_some() {
        return Some(format!("{}:{} -> open (tcp)", ip, port));
    }
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    banner();
    let cli = Cli::parse();

    let ports: Vec<u16> = if cli.all_ports {
        (1u16..=65535u16).collect()
    } else if let Some(ps) = &cli.ports {
        parse_ports(ps).unwrap_or_else(|e| {
            eprintln!("Ports parse error: {e}"); std::process::exit(2);
        })
    } else {
        default_ports()
    };

    let ips = expand_targets(&cli).await.unwrap_or_else(|e| {
        eprintln!("Target error: {e}");
        std::process::exit(2);
    });

    println!("Targets: {} | Ports: {} | concurrency={} | timeout={}ms",
        ips.len(), ports.len(), cli.concurrency, cli.timeout_ms);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .gzip(true)
        .timeout(Duration::from_millis(cli.timeout_ms * 2))
        .build()?;

    let sem = Arc::new(Semaphore::new(cli.concurrency));
    let mut futs = FuturesUnordered::new();

    for ip in ips {
        for &p in &ports {
            let client = client.clone();
            let sem = sem.clone();
            let timeout_ms = cli.timeout_ms;
            futs.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.ok();
                probe_one(ip, p, &client, timeout_ms).await
            }));
        }
    }

    while let Some(res) = futs.next().await {
        if let Ok(Some(line)) = res { println!("{line}"); }
    }

    Ok(())
}
