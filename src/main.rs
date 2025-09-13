use anyhow::{anyhow, Result};
use clap::Parser;
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(
    name = "webfigchecker",
    about = "Scan IP/ASN/CIDR/range to detect MikroTik WebFig"
)]
struct Args {
    /// Single IP (ignored if --asn/--cidr/--ip-range used)
    #[arg(required = false)]
    ip: Option<String>,

    /// Scan an Autonomous System, e.g. AS15169
    #[arg(long)]
    asn: Option<String>,

    /// CIDR network to expand, e.g. 192.168.1.0/24
    #[arg(long)]
    cidr: Option<String>,

    /// IPv4 range: start-end, e.g. 192.168.1.10-192.168.1.50 or 192.168.1.10-50
    #[arg(long = "ip-range")]
    ip_range: Option<String>,

    /// Single port (if not using --all-ports/--ports)
    #[arg(short, long)]
    port: Option<u16>,

    /// Comma separated ports (supports ranges), e.g. 80,443,8080-8090,8291
    #[arg(long)]
    ports: Option<String>,

    /// Scan ALL ports (1..=65535)
    #[arg(long)]
    all_ports: bool,

    /// For ASN/CIDR: sample N IPs per prefix (default 1)
    #[arg(long, default_value_t = 1)]
    per_prefix: usize,

    /// EXPENSIVE: expand every IP in every prefix for ASN/CIDR
    #[arg(long)]
    expand_all_ips: bool,

    /// Max concurrent connections
    #[arg(short = 'c', long, default_value_t = 400)]
    concurrency: usize,

    /// Per-connection timeout (ms)
    #[arg(long = "timeout-ms", default_value_t = 800)]
    timeout_ms: u64,
}


fn print_banner() {
    println!("=======================================");
    println!("   🚀 Welcome to WebFig Checker Tool   ");
    println!("   Founder: Ecbrain                    ");
    println!("   Co-Founder: p4oT09                  ");
    println!("=======================================\n");
}

#[tokio::main]
async fn main() -> Result<()> {
    print_banner();
    let args = Args::parse();
    let timeout_dur = Duration::from_millis(args.timeout_ms);
    let portset = build_portset(&args)?;

    // Build list of target IPs
    let targets: Vec<IpAddr> = if let Some(asn) = args.asn.as_deref() {
        let prefixes = fetch_asn_prefixes(asn).await?;
        eprintln!("ASN {} -> {} prefixes", asn, prefixes.len());
        expand_prefixes(&prefixes, args.per_prefix, args.expand_all_ips)?
    } else if let Some(c) = args.cidr.as_deref() {
        let net: IpNet = c.parse()?;
        expand_prefixes(&[net], args.per_prefix, args.expand_all_ips)?
    } else if let Some(r) = args.ip_range.as_deref() {
        expand_ipv4_range(r)?
    } else if let Some(ip) = args.ip.as_deref() {
        vec![ip.parse()?]
    } else {
        return Err(anyhow!(
            "Give one of: <IP> | --asn AS12345 | --cidr NET | --ip-range A-B"
        ));
    };

    eprintln!(
        "Targets: {} | Ports: {} | concurrency={} | timeout={}ms",
        targets.len(),
        portset.len(),
        args.concurrency,
        args.timeout_ms
    );

    let sem =  Arc::new(Semaphore::new(args.concurrency));
    let mut tasks = Vec::new();

    for ip in targets {
        for &port in &portset {
            let sem = sem.clone();
            let to = timeout_dur;
            tasks.push(tokio::spawn(async move {
                let _p = sem.acquire().await.unwrap();
                if let Ok(Some(prod)) = check_webfig(ip, port, to).await {
                    println!("{}:{} -> {}", ip, port, prod);
                }
            }));
        }
    }

    for t in tasks { let _ = t.await; }
    Ok(())
}

/* ---------- targets helpers ---------- */

#[derive(Deserialize)]
struct BgpviewPrefixes { data: BgpviewData }
#[derive(Deserialize)]
struct BgpviewData {
    ipv4_prefixes: Vec<PrefixEntry>,
    #[allow(dead_code)]
    ipv6_prefixes: Vec<PrefixEntry>,
}
#[derive(Deserialize)]
struct PrefixEntry { prefix: String }

async fn fetch_asn_prefixes(asn_input: &str) -> Result<Vec<IpNet>> {
    // Must be like "AS12345"
    let mut asn = asn_input.trim().to_uppercase();
    if !asn.starts_with("AS") { asn = format!("AS{}", asn); }
    let url = format!("https://api.bgpview.io/asn/{}/prefixes", asn);

    let client = reqwest::Client::builder()
        .user_agent("webfigchecker/1.3")
        .build()?;

    let resp: BgpviewPrefixes = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut out = Vec::new();
    for e in resp.data.ipv4_prefixes {
        if let Ok(net) = e.prefix.parse::<IpNet>() {
            if net.addr().is_ipv4() { out.push(net); }
        }
    }
    Ok(out)
}

fn expand_prefixes(prefixes: &[IpNet], per: usize, all: bool) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for p in prefixes {
        if let IpNet::V4(v4) = p {
            if all {
                for ip in v4.hosts() { ips.push(IpAddr::V4(ip)); }
            } else {
                let mut n = 0usize;
                for ip in v4.hosts() {
                    ips.push(IpAddr::V4(ip));
                    n += 1; if n >= per { break; }
                }
            }
        }
    }
    Ok(ips)
}

fn expand_ipv4_range(spec: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow!("ip-range must be like 192.168.1.10-192.168.1.50 or 192.168.1.10-50"));
    }
    let start: Ipv4Addr = parts[0].parse()?;
    let end: Ipv4Addr = if parts[1].contains('.') {
        parts[1].parse()?
    } else {
        let mut s = parts[0].split('.').collect::<Vec<_>>();
        s[3] = parts[1];
        Ipv4Addr::from_str(&s.join("."))?
    };
    if u32::from(start) > u32::from(end) { return Err(anyhow!("start > end")); }
    let mut v = Vec::new();
    let (mut a, b) = (u32::from(start), u32::from(end));
    while a <= b { v.push(IpAddr::V4(Ipv4Addr::from(a))); a += 1; }
    Ok(v)
}

/* ---------- ports helpers ---------- */

fn build_portset(a: &Args) -> Result<Vec<u16>> {
    if a.all_ports { return Ok((1u16..=65535u16).collect()); }
    if let Some(s) = &a.ports {
        let mut v: Vec<u16> = Vec::new();
        for item in s.split(',') {
            let item = item.trim();
            if item.is_empty() { continue; }
            if let Some((start_str, end_str)) = item.split_once('-') {
                let start: u16 = start_str.trim().parse()?;
                let end: u16 = end_str.trim().parse()?;
                let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
                for p in lo..=hi { v.push(p); }
            } else {
                v.push(item.parse::<u16>()?);
            }
        }
        v.sort_unstable();
        v.dedup();
        return Ok(v);
    }
    if let Some(p) = a.port { return Ok(vec![p]); }
    Ok(vec![80, 443, 8080, 8291])
}
    if let Some(s) = &a.ports {
        let mut v = Vec::new();
        for p in s.split(',') { v.push(p.trim().parse::<u16>()?); }
        v.sort_unstable(); v.dedup(); return Ok(v);
    }
    if let Some(p) = a.port { return Ok(vec![p]); }
    Ok(vec![80, 443, 8080, 8291])
}

/* ---------- detector ---------- */

async fn check_webfig(ip: IpAddr, port: u16, to: Duration) -> Result<Option<String>> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = match timeout(to, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s, _ => return Ok(None),
    };

    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: webfigchecker/1.3\r\nConnection: close\r\n\r\n",
        ip
    );
    let _ = stream.write_all(req.as_bytes()).await;

    let mut buf = vec![0u8; 4096];
    let n = match timeout(to, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n, _ => return Ok(None),
    };
    let body = String::from_utf8_lossy(&buf[..n]).to_lowercase();

    let has = body.contains("webfig") || body.contains("mikrotik") || body.contains("routeros");
    if !has {
        let re = Regex::new(r"routeros|mikrotik|webfig").unwrap();
        if !re.is_match(&body) { return Ok(None); }
    }
    let product = extract_product(&body).unwrap_or_else(|| "WebFig".to_string());
    Ok(Some(product))
}

fn extract_product(s: &str) -> Option<String> {
    for p in [
        r"(routeros\s*v?[\d\.]+)",
        r"(mikrotik\s*routeros\s*v?[\d\.]+)",
        r"(webfig)",
        r"(mikrotik)",
    ] {
        if let Ok(re) = Regex::new(p) {
            if let Some(m) = re.captures(s) {
                return Some(m.get(1)?.as_str().trim().to_string());
            }
        }
    }
    None
}
