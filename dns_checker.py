import socket


from urllib.parse import urlparse


def parse_domain(url: str) -> str:
    parsed = urlparse(url)
    if 'www.' in parsed.netloc:
        return parsed.netloc[4:].replace('\n', '')
    return parsed.path.split('/')[0]


def get_site_ip(url: str):
    parsed_domain = parse_domain(url)
    print(parsed_domain)
    #print(socket.gethostbyname(parsed_domain))

get_site_ip('https://www.ipko.pl/logowanie')
