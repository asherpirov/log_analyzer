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

def port_to_protocol(data):
    return {row[3] : row[4] for row in data}

def analyze_suspicions(data):
    suspicion_dict = {}
    for row in data:
        ip = row[1]
        timestamp = row[0]
        port = row[3]
        size = int(row[5])

        if ip not in suspicion_dict:
            suspicion_dict[ip] = set()
        if not ip.startswith("10.") and not ip.startswith("192.168."):
            suspicion_dict[ip].add("EXTERNAL_IP")
        if port in [22,23,3389]:
            suspicion_dict[ip].add("SENSITIVE_PORT")
        if size > 5000:
            suspicion_dict[ip].add("LARGE_PACKET")
        time_part = timestamp.split(" ")[1]
        hour = int(time_part.split(':')[0])
        if 0 <= hour < 6:
            suspicion_dict[ip].add("NIGHT_ACTIVITY")
    return suspicion_dict

def filter_suspicions(suspicion_dict):
    filtered_items = filter(lambda item: len(item[1]) >= 2, suspicion_dict.items())
    return dict(filtered_items)