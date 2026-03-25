# nmap2drawio

Must run as root to enable SYN TCP scan (`-sS`).

## Scan 1 — Fast Discovery (< 30 min)

Quick host discovery and top-100 port scan. Uses TCP SYN probes on common ports, ICMP echo, and SNMP (UDP 161) to find live hosts — then only scans those. Skips DNS resolution (`-n`) for speed.

Run this first to get a rapid network map and identify live hosts for the follow-up scans.

```bash
nmap -T4 --traceroute -n -sS -F --stats-every 10s \
  -PS22,23,53,80,135,443,445,3389,5985,8080 -PE -PU161 \
  -oX out_172_scan.xml \
  172.17.0.0/30 172.17.1.0/24 172.17.2.0/24 172.17.3.0/24 \
  172.17.4.0/24 172.17.5.0/24 172.17.6.0/24 172.17.7.0/24 \
  172.17.8.0/24 172.29.255.0/30 172.31.251.0/24 172.31.252.0/24 \
  172.31.254.0/24 172.31.255.0/24 172.30.255.0/24
```

## Scan 2 — Detailed TCP (< 6 hrs)

Deep TCP scan with service/version detection (`-sV`), OS fingerprinting (`-O`), and default NSE scripts (`-sC`). Scans all 3,336 IPs with `-Pn` (no host discovery skip) to catch hosts that were invisible to Scan 1. Covers all privileged ports (1-1024) plus key high ports for databases, remote management, and web services.

Run after Scan 1. Can run in parallel with Scan 3.

```bash
nmap -T4 --traceroute -Pn -sS -sV --version-intensity 5 -O -sC \
  --stats-every 30s \
  -p 1-1024,1433,1521,3306,3389,5432,5060,5061,5985,5986,8080,8443,8888,9090,9443,27017 \
  -oX out_172_detailed.xml \
  172.17.0.0/30 172.17.1.0/24 172.17.2.0/24 172.17.3.0/24 \
  172.17.4.0/24 172.17.5.0/24 172.17.6.0/24 172.17.7.0/24 \
  172.17.8.0/24 172.29.255.0/30 172.31.251.0/24 172.31.252.0/24 \
  172.31.254.0/24 172.31.255.0/24 172.30.255.0/24
```

## Scan 3 — UDP (< 2 hrs)

UDP service scan against live hosts only (from Scan 1 results). UDP is kept separate because it is significantly slower than TCP — each non-responsive port requires a full timeout + retries. Limiting to known-alive hosts avoids wasting hours on dead IPs. Covers DNS, DHCP, TFTP, NTP, SNMP, IPsec, syslog, SSDP, and mDNS.

Run after Scan 1. Can run in parallel with Scan 2.

```bash
# Extract live hosts from Scan 1
grep -oP 'addr="\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' out_172_scan.xml \
  | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > live_hosts.txt

# UDP scan against live hosts only
nmap -T4 -Pn -sU -sV --stats-every 30s \
  -p 53,67,68,69,123,161,162,500,514,1900,4500,5353 \
  -oX out_172_udp.xml \
  -iL live_hosts.txt
```

## Workflow

| Order | Scan | Targets | Est. Time |
|-------|------|---------|-----------|
| 1st | Fast Discovery | All subnets | ~10-30 min |
| 2nd | Detailed TCP | All subnets (`-Pn`) | ~4-6 hrs |
| 2nd (parallel) | UDP | Live hosts only | ~1-2 hrs |
