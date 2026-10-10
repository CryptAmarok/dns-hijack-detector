from dns_checker import analyze_dns, fetch_dns


def main() -> None:
    while True:
        try:
            url = input("Enter the URL: ").strip()
        except KeyboardInterrupt:
            break

        if not url:
            continue

        print(f"Checking {url}...")
        try:
            records = fetch_dns(url)

            analysis = analyze_dns(records)

            ip_match = analysis.get('ip_match')
            asn_match = analysis.get('asn_match')

            print(f"Local IP: {records.local_ip}")

            if ip_match is None or asn_match is None:
                print("UNKNOWN: Unable to determine DNS status")
            elif ip_match and asn_match:  # T T Both IP and ASN True
                print("GOOD: DNS responses are consistent")
            elif not ip_match and not asn_match:  # F F Both IP and ASN False
                print("SUSPICIOUS: DNS responses differ between resolvers")
            elif not ip_match and asn_match:  # F T
                print("GOOD: Possible CDN or load balancing")
            elif ip_match and not asn_match: # Only IP True
                print(
                    "WARNING: Inconsistent ASN information. "
                    "Further investigation is required")

        except RuntimeError as e:
            print(f"Error: {e}")

        except Exception as e:
            print(f"Unknown Error: {e}")


if __name__ == '__main__':
    main()
