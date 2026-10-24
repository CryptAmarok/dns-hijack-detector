import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import requests


@dataclass
class DNSRecords:
    domain: str
    local_ip: str | None
    reference_records: tuple[tuple[str, ...] | None, tuple[str, ...] | None]


@dataclass
class DNSAnalysis:
    ip_match: bool
    asn_match: bool


def parse_domain(url: str) -> str:
    parsed = urlparse(url)

    # Fallback to path if netloc is empty, then drop URL path/query
    host = (parsed.netloc or parsed.path).split('/')[0]
    return host.removeprefix('www.')


def get_local_ip(url: str) -> str | None:
    """Get the IP address of a domain using the system's resolver"""
    try:
        parsed_domain = parse_domain(url)
        return socket.gethostbyname(parsed_domain)
    except socket.gaierror:
        print(f"Error: Couldn't connect with site {parsed_domain}")
        return None


def get_trusted_ips(
        url: str,
        doh_url: str = 'https://cloudflare-dns.com/dns-query'
) -> tuple[str, ...] | None:

    parsed_domain = parse_domain(url)

    # Prevent DNS query if the domain is empty
    if not parsed_domain:
        return None

    # Create DNS query for the trusted resolver
    query = dns.message.make_query(parsed_domain, dns.rdatatype.A)

    try:
        # send query over DoH
        response = dns.query.https(
            query, doh_url, http_version=dns.query.HTTPVersion.H2)

        if response.rcode() == dns.rcode.NXDOMAIN:
            print(f"The {parsed_domain} does not exist")
            return None

        if not response.answer:
            return None

        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                return tuple(str(record.address) for record in rrset)

    except dns.exception.DNSException as e:
        print(f"DNS Resolution Error for {parsed_domain}: {e}")
        return None


def get_asn(ip_address: str | None) -> int | None:
    """Get the ASN number to verify the IP address owner"""
    if ip_address is None:
        return None

    api_url = f"https://ipwho.is/{ip_address}"

    try:
        response = requests.get(api_url)
        response.raise_for_status()
        res = response.json()
    except (requests.RequestException, ValueError):
        return None

    if not res.get("success"):
        return None

    connection = res.get("connection")
    if connection:
        return connection.get("asn")
    return None


def fetch_dns(url: str) -> DNSRecords:
    local_ip = get_local_ip(url)
    cloudflare_ip = get_trusted_ips(
        url, "https://cloudflare-dns.com/dns-query"
    )

    # Second trusted resolver for better verification
    google_ip = get_trusted_ips(
        url, "https://dns.google/dns-query"
    )

    reference_ips = (cloudflare_ip, google_ip)

    return DNSRecords(
        domain=parse_domain(url),
        local_ip=local_ip,
        reference_records=reference_ips
    )


def analyze_dns(dns_record: DNSRecords):

    result = {
        'ip_match': False,
        'asn_match': False
    }
    local = dns_record.local_ip

    if local is None:
        raise RuntimeError("Couldn't resolve domain to an IP address")

    if any(local in ref
           for ref in dns_record.reference_records
           if ref is not None):
        result['ip_match'] = True

    local_asn = get_asn(local)

    reference_asn_1 = get_asn(dns_record.reference_records[0][0])
    reference_asn_2 = get_asn(dns_record.reference_records[1][0])

    if local_asn in (reference_asn_1, reference_asn_2):
        result['asn_match'] = True

    return result
    
