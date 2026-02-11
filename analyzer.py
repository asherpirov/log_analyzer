import collections
from typing import Counter


def get_external_ips(data):
    external_ips = [row[1] for row in data if not row[1].startswith(("192.168.", "10."))]
    return external_ips

def get_sensitive_port_traffic(data):
    sensitive_ports = ["22","23", "3389"]
    sensitive_traffic = [row for row in data if row[3] in sensitive_ports]
    return sensitive_traffic

def get_large_packets(data):
    large_packets = [row for row in data if int(row[5]) > 5000]
    return large_packets

def tag_traffic_size(data):
    tags = ["LARGE" if int(row[5]) > 5000 else "NORMAL" for row in data]
    return tags

def count_requests_per_ip(data):
    all_ips = [row[1] for row in data]
    return Counter(all_ips)