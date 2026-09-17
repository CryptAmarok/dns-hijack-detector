import dns.rcode
import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import socket
import requests
from urllib.parse import urlparse


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


def get_trusted_ip(
        url: str,
        doh_url: str = 'https://cloudflare-dns.com/dns-query'
) -> str | None:

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

        answer = response.answer[0][0]
        return answer.address

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
