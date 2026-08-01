#import socket


from urllib.parse import urlparse


def parse_domain(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.netloc or parsed.path).split('/')[0]


def get_site_ip(site_url):
    pass
