#!/usr/bin/env python3

import sys
import dns.resolver
from dns.exception import DNSException
import nmap

def parse_zone_file(zone_file_path, origin_domain):
    """
    Parse a DNS zone file to extract records.
    """
    try:
        zone = dns.zone.from_file(zone_file_path, origin=origin_domain)
    except DNSException as e:
        print(f"Error reading zone file: {e}")
        return

    records = {"A": [], "CNAME": []}

    for name, node in zone.nodes.items():
        rdatasets = node.rdatasets
        for rdataset in rdatasets:
            record_type = dns.rdatatype.to_text(rdataset.rdtype)
            if record_type == "A":
                for rdata in rdataset:
                    records["A"].append((name.to_text(origin_domain), rdata.address))
            elif record_type == "CNAME":
                for rdata in rdataset:
                    records["CNAME"].append((name.to_text(origin_domain), rdata.target.to_text()))

    return records

def resolve_to_ip(domain):
    """
    Resolve a domain name to its IP address.
    """
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [answer.address for answer in answers]
    except DNSException as e:
        print(f"Error resolving {domain}: {e}")
        return []

def dns_record_dump(records):
    """
    Dump the DNS records to stdout.
    """
    print("Parsed DNS Records:")
    print("A Records:")
    for name, ip in records["A"]:
        print(f"  {name} -> {ip}")

    print("\nCNAME Records:")
    for name, target in records["CNAME"]:
        print(f"  {name} -> {target}")

    # Optionally resolve the CNAME targets to IPs
    print("\nResolving CNAME Targets:")
    for name, target in records["CNAME"]:
        ips = resolve_to_ip(target)
        if ips:
            print(f"  {target} resolves to {', '.join(ips)}")

def nmap_a_records(records, origin_domain, ports_to_scan):
    """
    Perform an nmap scan on A records extracted from a DNS zone file.

    This function reads a DNS zone file to extract A records, then uses
    nmap to scan the specified ports for these records. It outputs the scanning 
    results including the protocols and state of each scanned port.

    Args:
        records (dict): DNS records with 'A' and 'CNAME' keys.
        origin_domain (str): Origin domain for resolving records.
        ports_to_scan (list): List of ports to scan. Default is ['80', '443'].

    Raises:
        dns.resolver.NoAnswer: If no A record is found for a CNAME.
    """
    a_records = [name for name, _ in records["A"]]
    a_records = [name.replace('@', origin_domain) for name in a_records]
    a_records = [f"{name}.{origin_domain}" if name != origin_domain else name for name in a_records]

    scanner = nmap.PortScanner()

    # Check for NX records
    nx_records = []
    for name in a_records:
        try:
            dns.resolver.resolve(name, 'A')
        except dns.resolver.NXDOMAIN:
            a_records.remove(name)
            nx_records.append(name)

    if nx_records:
        print("The following records are not resolvable:")
        for record in nx_records:
            print(f"  {record}")
    
    # Scan A records
    print("Scanning A records:")
    
        
        
    try:
        scanner.scan(' '.join(map(str, a_records)),
                     ', '.join(map(str, ports_to_scan)),
                     arguments='-Pn'
                     )
        
        for host in scanner.all_hosts():
            for protocol in scanner[host].all_protocols():
                for port, port_info in scanner[host][protocol].items():
                    print(f"{host} Protocol: {protocol} Port: {port} State: {port_info['state']}")

    except nmap.PortScannerError as e:
        print(f"Error scanning A records: {e}")


    return scanner


if __name__ == "__main__":
    # get zone name as command line argument
    if len(sys.argv) < 2:
        print("Usage: python dns_parser.py <zone_name> <zone_file>")
        exit(1)

    origin_domain = sys.argv[1]
    zone_file_path = sys.argv[2]
    ports_to_scan = ['443']
    ports_to_scan = [
        '21',  # FTP
        '22',  # SSH
        '53',  # DNS
        '67',  # DHCP
        '68',  # DHCP
        '80',  # HTTP
        '88',  # Kerberos
        '110', # POP3
        '111', # RPC
        '135', # MS-RPC
        '139', # SMB
        '143', # IMAP
        '443', # HTTPS
        '445', # SMB over TCP
        '465', # SMTP over SSL
        '587', # Mail submission agent
        '631', # CUPS
        '993', # IMAP over SSL
        '995'  # POP3 over SSL
    ]

    records = parse_zone_file(zone_file_path, origin_domain)
    if not records:
        exit(1)

    # dns_record_dump(records)
       
    scan = nmap_a_records(records, origin_domain, ports_to_scan)
    with open(f"{origin_domain}.csv", 'w') as f:
        f.write(scan.csv())
        f.close()

