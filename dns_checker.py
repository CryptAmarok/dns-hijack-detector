import socket
from urllib.parse import urlparse


def parse_domain(url: str) -> str:
    parsed = urlparse(url)

    # Fallback to path if netloc is empty, then drop URL path/query
    host = (parsed.netloc or parsed.path).split('/')[0]
    return host.removeprefix('www.')


def get_site_ip(url: str) -> str | None:
    try:
        parsed_domain = parse_domain(url)
        return socket.gethostbyname(parsed_domain)
    except socket.gaierror:
        print(f"Error: Couldn't connect with site {parsed_domain}")
        return None