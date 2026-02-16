from reader import load_csv
from analyzer import *


def main():
    log_path = "network_traffic.log"
    data = load_csv(log_path)
    print(len(data), "rows from log file.")

    ip_counts = count_requests_per_ip(data)
    print(dict(list(ip_counts.items())[:3]))

    protocols = port_to_protocol(data)
    print(dict(list(protocols.items())[:3]))

    suspicions = analyze_suspicions(data)
    print(f"Analyzed {len(suspicions)} unique IPs.")

    severe_threats = filter_suspicions(suspicions)

    print(f"Found {len(severe_threats)} suspicious IPs:")
    for ip, threats in severe_threats.items():
        print(f" IP: {ip} -> Threats: {threats}")


if __name__ == "__main__":
    main()