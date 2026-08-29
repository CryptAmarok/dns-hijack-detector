import dns.resolver
import dns.exception
import socket
import requests
from urllib.parse import urlparse


def parse_domain(url: str) -> str:
    parsed = urlparse(url)

    # Fallback to path if netloc is empty, then drop URL path/query
    host = (parsed.netloc or parsed.path).split('/')[0]
    return host.removeprefix('www.')


def get_site_ip(url: str) -> str | None:
    """Get the IP address of a domain using the system's resolver"""
    try:
        parsed_domain = parse_domain(url)
        return socket.gethostbyname(parsed_domain)
    except socket.gaierror:
        print(f"Error: Couldn't connect with site {parsed_domain}")
        return None


def get_trusted_ip(url: str, dns_server: str = '1.1.1.1') -> str | None:

    custom_resolver = dns.resolver.Resolver()
    custom_resolver.nameservers = [dns_server]

    parsed_domain = parse_domain(url)

    # Prevent DNS query if parsed_domain is an empty string
    if parsed_domain:
        try:
            answers = custom_resolver.resolve(parsed_domain)
            return next(answer.to_text() for answer in answers)
        except dns.resolver.NXDOMAIN:
            print(f"The {parsed_domain} does not exist")
            return None
        except dns.exception.DNSException as e:
            print(f"DNS Resolution Error for {parsed_domain}: {e}")
            return None

    return None


def get_asn(ip_address: str) -> int | None:
    """Get the ASN number to verify the IP address owner"""
    if ip_address is None:
        return None

    api_url = f"https://ipwho.is/{ip_address}"

    response = requests.get(api_url)
    res = response.json()

    if not res.get("success"):
        return None

    connection = res.get("connection")
    if connection:
        return connection.get("asn")
    return None
