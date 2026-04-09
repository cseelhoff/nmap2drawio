#!/usr/bin/env python3
"""
Portable Windows DNS Server Record Enumerator

Three methods, ranked by portability:
  1. LDAP - Query AD-integrated DNS zones directly from Active Directory
  2. AXFR - DNS zone transfer (if server allows it)
  3. WMI  - Remote WMI query (Windows only, no RSAT needed)

Usage:
  python3 dns_enum.py --method ldap --server dc1.domain.com --domain domain.com
  python3 dns_enum.py --method ldap --server dc1.domain.com --domain domain.com -u admin -p pass
  python3 dns_enum.py --method axfr --server 10.0.0.1 --domain domain.com
  python3 dns_enum.py --method wmi  --server dc1.domain.com

Dependencies: pip install ldap3 dnspython
"""

import argparse
import json
import struct
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# Method 1: LDAP - Query AD-Integrated DNS zones from Active Directory
# ---------------------------------------------------------------------------
# DNS records in AD live under:
#   CN=MicrosoftDNS,DC=DomainDnsZones,DC=<domain>,DC=<tld>
#   CN=MicrosoftDNS,DC=ForestDnsZones,DC=<domain>,DC=<tld>
#   CN=MicrosoftDNS,CN=System,DC=<domain>,DC=<tld>  (legacy)
#
# Each record is an object with attribute 'dnsRecord' (binary blob).
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = {
    0x0000: "ZERO",
    0x0001: "A",
    0x0002: "NS",
    0x0005: "CNAME",
    0x0006: "SOA",
    0x000C: "PTR",
    0x000F: "MX",
    0x0010: "TXT",
    0x001C: "AAAA",
    0x0021: "SRV",
}


def parse_dns_record_blob(blob):
    """
    Parse the binary dnsRecord attribute from AD.
    MS-DNSP section 2.3.2.2 - DNS_RPC_RECORD structure.
    """
    if len(blob) < 24:
        return None

    data_length = struct.unpack('<H', blob[0:2])[0]
    record_type = struct.unpack('<H', blob[2:4])[0]
    # version = blob[4]
    # rank = blob[5]
    # flags = struct.unpack('<H', blob[6:8])[0]
    # serial = struct.unpack('<I', blob[8:12])[0]
    ttl_raw = blob[12:16]
    ttl = struct.unpack('>I', ttl_raw)[0]  # TTL is big-endian
    # reserved = struct.unpack('<I', blob[16:20])[0]
    timestamp = struct.unpack('<I', blob[20:24])[0]

    rtype_name = DNS_RECORD_TYPES.get(record_type, f"TYPE({record_type})")
    rdata = blob[24:24 + data_length]
    rdata_str = _parse_rdata(record_type, rdata, blob)

    # Timestamp: 0 = static, otherwise hours since Jan 1, 1601
    ts_str = "static"
    if timestamp > 0:
        try:
            epoch_hours = timestamp - 3335568  # hours between 1601 and 1970
            ts_str = datetime.utcfromtimestamp(epoch_hours * 3600).isoformat()
        except (OSError, OverflowError, ValueError):
            ts_str = f"raw:{timestamp}"

    return {
        "type": rtype_name,
        "ttl": ttl,
        "timestamp": ts_str,
        "data": rdata_str,
    }


def _decode_dns_name(data, offset=0):
    """Decode a DNS name from the binary record data (length-prefixed labels)."""
    labels = []
    pos = offset
    while pos < len(data):
        label_len = data[pos]
        if label_len == 0:
            break
        pos += 1
        if pos + label_len > len(data):
            break
        labels.append(data[pos:pos + label_len].decode('utf-8', errors='replace'))
        pos += label_len
    return '.'.join(labels) if labels else '.'


def _parse_rdata(rtype, rdata, full_blob):
    """Best-effort parse of common record types."""
    try:
        if rtype == 0x0001 and len(rdata) == 4:  # A
            return '.'.join(str(b) for b in rdata)

        if rtype == 0x001C and len(rdata) == 16:  # AAAA
            import socket
            return socket.inet_ntop(socket.AF_INET6, rdata)

        if rtype in (0x0002, 0x0005, 0x000C):  # NS, CNAME, PTR
            return _decode_dns_name(rdata)

        if rtype == 0x000F and len(rdata) >= 4:  # MX
            preference = struct.unpack('<H', rdata[0:2])[0]
            name = _decode_dns_name(rdata, 2)
            return f"{preference} {name}"

        if rtype == 0x0021 and len(rdata) >= 8:  # SRV
            priority = struct.unpack('<H', rdata[0:2])[0]
            weight = struct.unpack('<H', rdata[2:4])[0]
            port = struct.unpack('<H', rdata[4:6])[0]
            target = _decode_dns_name(rdata, 6)
            return f"{priority} {weight} {port} {target}"

        if rtype == 0x0006 and len(rdata) > 20:  # SOA
            # Primary NS starts at the beginning
            return "(SOA record)"

        if rtype == 0x0010:  # TXT
            return rdata.decode('utf-8', errors='replace')

    except Exception:
        pass

    return rdata.hex()


def enum_ldap(server, domain, username=None, password=None, use_ssl=False):
    """Enumerate DNS records via LDAP from Active Directory."""
    try:
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    except ImportError:
        print("ERROR: ldap3 not installed. Run: pip install ldap3", file=sys.stderr)
        sys.exit(1)

    domain_parts = domain.split('.')
    domain_dn = ','.join(f'DC={p}' for p in domain_parts)

    # Search bases for AD-integrated DNS zones
    search_bases = [
        f"CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}",
        f"CN=MicrosoftDNS,DC=ForestDnsZones,{domain_dn}",
        f"CN=MicrosoftDNS,CN=System,{domain_dn}",
    ]

    port = 636 if use_ssl else 389
    ldap_server = Server(server, port=port, use_ssl=use_ssl, get_info=ALL)

    conn_kwargs = {}
    if username and password:
        # Support DOMAIN\user or user@domain formats
        conn_kwargs['user'] = username
        conn_kwargs['password'] = password
        if '\\' in username:
            conn_kwargs['authentication'] = NTLM

    conn = Connection(ldap_server, auto_bind=True, **conn_kwargs)
    print(f"[+] Connected to {server}")

    all_records = {}

    for base_dn in search_bases:
        print(f"[*] Searching: {base_dn}")

        # First, enumerate zones
        try:
            conn.search(
                base_dn,
                '(objectClass=dnsZone)',
                search_scope=SUBTREE,
                attributes=['name']
            )
        except Exception as e:
            print(f"    [-] Not accessible: {e}")
            continue

        zones = [entry.name.value for entry in conn.entries if hasattr(entry, 'name')]
        print(f"    [+] Found {len(zones)} zone(s): {', '.join(zones)}")

        for zone in zones:
            zone_dn = f"DC={zone},{base_dn}"
            zone_records = []

            try:
                conn.search(
                    zone_dn,
                    '(objectClass=dnsNode)',
                    search_scope=SUBTREE,
                    attributes=['distinguishedName', 'dnsRecord', 'dNSTombstoned', 'name']
                )
            except Exception as e:
                print(f"    [-] Error querying zone {zone}: {e}")
                continue

            for entry in conn.entries:
                node_name = str(entry.name) if hasattr(entry, 'name') else '?'

                # Skip tombstoned records
                if hasattr(entry, 'dNSTombstoned') and str(entry.dNSTombstoned) == 'TRUE':
                    continue

                if not hasattr(entry, 'dnsRecord') or not entry.dnsRecord:
                    continue

                # dnsRecord is multi-valued; each value is a binary blob
                for blob in entry.dnsRecord.values:
                    parsed = parse_dns_record_blob(blob)
                    if parsed:
                        record = {
                            "name": node_name,
                            "zone": zone,
                            **parsed
                        }
                        zone_records.append(record)

            all_records[zone] = zone_records
            print(f"    [+] Zone '{zone}': {len(zone_records)} record(s)")

    conn.unbind()
    return all_records


# ---------------------------------------------------------------------------
# Method 2: AXFR - DNS Zone Transfer
# ---------------------------------------------------------------------------

def enum_axfr(server, domain, zones=None):
    """Enumerate DNS records via AXFR zone transfer."""
    try:
        import dns.query
        import dns.zone
        import dns.resolver
        import dns.rdatatype
    except ImportError:
        print("ERROR: dnspython not installed. Run: pip install dnspython", file=sys.stderr)
        sys.exit(1)

    if zones is None:
        zones = [domain]

    all_records = {}

    for zone_name in zones:
        print(f"[*] Attempting AXFR for zone: {zone_name} from {server}")
        zone_records = []

        try:
            xfr = dns.query.xfr(server, zone_name, timeout=10)
            zone = dns.zone.from_xfr(xfr)

            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        zone_records.append({
                            "name": str(name),
                            "zone": zone_name,
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "ttl": rdataset.ttl,
                            "data": str(rdata),
                        })

            print(f"    [+] Zone '{zone_name}': {len(zone_records)} record(s)")

        except dns.query.TransferError:
            print(f"    [-] Zone transfer refused for {zone_name} (server denies AXFR)")
        except Exception as e:
            print(f"    [-] AXFR failed for {zone_name}: {e}")

        all_records[zone_name] = zone_records

    return all_records


# ---------------------------------------------------------------------------
# Method 3: WMI - Query MicrosoftDNS WMI namespace (Windows only, no RSAT)
# ---------------------------------------------------------------------------

WMI_SCRIPT = r'''
# WMI DNS Enumeration - No DnsServer module needed
# Run on Windows with access to the DNS server's WMI namespace
param(
    [Parameter(Mandatory=$true)]
    [string]$DnsServer
)

$ErrorActionPreference = "Stop"

Write-Output "[+] Querying DNS server $DnsServer via WMI (no RSAT required)..."

try {
    $zones = Get-CimInstance -Namespace "root\MicrosoftDNS" -ClassName "MicrosoftDNS_Zone" -ComputerName $DnsServer
} catch {
    Write-Error "Failed to connect to WMI on $DnsServer. Ensure WMI access is allowed. Error: $_"
    exit 1
}

$results = @()
foreach ($zone in $zones) {
    Write-Output "[*] Zone: $($zone.Name)"
    $records = Get-CimInstance -Namespace "root\MicrosoftDNS" -ClassName "MicrosoftDNS_ResourceRecord" -ComputerName $DnsServer -Filter "DomainName='$($zone.Name)'"

    foreach ($record in $records) {
        $results += [PSCustomObject]@{
            Zone       = $zone.Name
            Owner      = $record.OwnerName
            RecordType = $record.TextRepresentation.Split(" ")[2]
            TTL        = $record.TextRepresentation.Split(" ")[1]
            Data       = ($record.TextRepresentation.Split(" ") | Select-Object -Skip 3) -join " "
        }
        Write-Output ("  {0,-40} {1,-8} {2}" -f $record.OwnerName, $record.TextRepresentation.Split(" ")[2], (($record.TextRepresentation.Split(" ") | Select-Object -Skip 3) -join " "))
    }
}

# Export to JSON
$results | ConvertTo-Json -Depth 3 | Out-File "dns_records.json" -Encoding UTF8
Write-Output "`n[+] Exported $($results.Count) records to dns_records.json"
'''


def generate_wmi_script():
    """Write the WMI-based PowerShell script to disk."""
    path = "dns_enum_wmi.ps1"
    with open(path, 'w') as f:
        f.write(WMI_SCRIPT)
    print(f"[+] WMI script written to {path}")
    print(f"    Run on Windows: powershell -ExecutionPolicy Bypass -File {path} -DnsServer <hostname>")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_records(all_records, output_format='table'):
    """Print enumerated records."""
    total = sum(len(v) for v in all_records.values())

    if output_format == 'json':
        print(json.dumps(all_records, indent=2, default=str))
        return

    # Table output
    print(f"\n{'='*90}")
    print(f" DNS Enumeration Results — {total} record(s)")
    print(f"{'='*90}")

    for zone, records in all_records.items():
        if not records:
            continue
        print(f"\n  Zone: {zone} ({len(records)} records)")
        print(f"  {'-'*86}")
        print(f"  {'Name':<35} {'Type':<8} {'TTL':<8} {'Data'}")
        print(f"  {'-'*86}")
        for r in sorted(records, key=lambda x: (x.get('type', ''), x.get('name', ''))):
            name = r.get('name', '?')
            rtype = r.get('type', '?')
            ttl = r.get('ttl', '?')
            data = r.get('data', '?')
            print(f"  {name:<35} {rtype:<8} {str(ttl):<8} {data}")

    print(f"\n{'='*90}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Portable Windows DNS Server Record Enumerator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # LDAP - enumerate AD-integrated DNS (works from Linux!)
  %(prog)s --method ldap --server dc1.corp.local --domain corp.local
  %(prog)s --method ldap --server dc1.corp.local --domain corp.local -u 'CORP\\\\admin' -p 'P@ss'

  # AXFR - zone transfer (if allowed by server)
  %(prog)s --method axfr --server 10.0.0.53 --domain corp.local

  # WMI - generate a PowerShell script (no RSAT needed)
  %(prog)s --method wmi
        """
    )

    parser.add_argument('--method', '-m', required=True,
                        choices=['ldap', 'axfr', 'wmi'],
                        help='Enumeration method')
    parser.add_argument('--server', '-s',
                        help='DNS server hostname or IP')
    parser.add_argument('--domain', '-d',
                        help='Domain name (e.g. corp.local)')
    parser.add_argument('--username', '-u', default=None,
                        help='Username for authentication (DOMAIN\\\\user or user@domain)')
    parser.add_argument('--password', '-p', default=None,
                        help='Password for authentication')
    parser.add_argument('--ssl', action='store_true',
                        help='Use LDAPS (port 636)')
    parser.add_argument('--zones', '-z', nargs='+', default=None,
                        help='Specific zone(s) to query (AXFR method)')
    parser.add_argument('--format', '-f', choices=['table', 'json'],
                        default='table', help='Output format')
    parser.add_argument('--output', '-o', default=None,
                        help='Write JSON results to file')

    args = parser.parse_args()

    if args.method == 'wmi':
        generate_wmi_script()
        return

    if not args.server or not args.domain:
        parser.error("--server and --domain are required for ldap/axfr methods")

    if args.method == 'ldap':
        results = enum_ldap(args.server, args.domain,
                            args.username, args.password, args.ssl)
    elif args.method == 'axfr':
        results = enum_axfr(args.server, args.domain, args.zones)

    print_records(results, args.format)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Results written to {args.output}")


if __name__ == '__main__':
    main()
