def extract_dns_zones(zone_file_path):
    try:
        with open(zone_file_path, 'r') as file:
            lines = file.readlines()
            zones = []
            current_zone = None
            for line in lines:
                if line.startswith(';') or line.strip() == '':
                    continue
                parts = line.split()
                if parts[0].endswith('.'):
                    current_zone = parts[0]
                    zones.append(current_zone)
                elif current_zone:
                    zones.append((current_zone, parts[0], parts[1], parts[2], parts[3]))
            return zones
    except Exception as e:
        print(f"Error reading zone file: {e}")

zones = extract_dns_zones("dns.txt")
for zone in zones:
    print(zone)