from dns_checker import get_site_ip, get_trusted_ip, get_asn


def main() -> None:
    url = input("Enter the URL: ")
    local_resolver_ip = get_site_ip(url)
    trusted_resolver_ip = get_trusted_ip(url)

    if local_resolver_ip is None:
        print("There is a problem with local resolver")
        return

    if trusted_resolver_ip is None:
        print("There is a problem with trusted resolver")
        return

    if local_resolver_ip == trusted_resolver_ip:
        print("DNS respones are comatible")
    else:
        local_asn = get_asn(local_resolver_ip)
        trusted_asn = get_asn(trusted_resolver_ip)
        if local_asn is None:
            print("Problem with local ASN")
            return
        if trusted_asn is None:
            print("Problem with trusted ASN")
            return
        if local_asn == trusted_asn:
            print("IP addresses are different, "
                  "but they belong to the same ASN.")
            print("No DNS anomaly detected.")
        else:
            print("Potential DNS anomaly detected")


if __name__ == '__main__':
    main()
