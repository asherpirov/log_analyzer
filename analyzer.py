def get_external_ips(data):
    external_ips = [row[1] for row in data if not row[1].startswith(("192.168.", "10."))]
    return external_ips