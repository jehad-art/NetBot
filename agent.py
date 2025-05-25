import os
import json
import socket
import ipaddress
import requests
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
import re
from discovery_db import is_known_device

load_dotenv()

API_BASE = os.getenv("API_BASE")
AGENT_TOKEN = os.getenv("AGENT_TOKEN")
SUBNET = os.getenv("SUBNET")
HEADERS = {"Authorization": f"Bearer {AGENT_TOKEN}"}
COMMON_PORTS = [22, 23, 80, 443, 161, 8291]
SQLITE_DB = "agent_devices.db"

commands = {
    "raw_config": "show running-config",
    "version": "show version",
    "interfaces": "show ip interface brief",
    "routes": "show ip route",
    "access_lists": "show access-lists",
    "ip_protocols": "show ip protocols",
    "cdp_neighbors": "show cdp neighbors detail"
}

# SQLite Helpers

def init_sqlite():
    conn = sqlite3.connect(SQLITE_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    last_seen TEXT,
                    provisioned INTEGER DEFAULT 0
                )''')
    conn.commit()
    conn.close()

def is_known_device(ip):
    conn = sqlite3.connect(SQLITE_DB)
    c = conn.cursor()
    c.execute("SELECT ip FROM devices WHERE ip = ?", (ip,))
    result = c.fetchone()
    conn.close()
    return result is not None

def mark_as_seen(ip):
    conn = sqlite3.connect(SQLITE_DB)
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute("INSERT OR REPLACE INTO devices (ip, last_seen) VALUES (?, ?)", (ip, now))
    conn.commit()
    conn.close()

# Discovery Scan

def scan_ports(ip, ports=COMMON_PORTS, timeout=1.5):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except:
                continue
    return open_ports

def scan_host(ip):
    open_ports = scan_ports(ip)
    if open_ports:
        return {
            "ip": ip,
            "open_ports": open_ports,
            "timestamp": datetime.utcnow().isoformat()
        }
    return None

def discover_hosts(subnet, max_workers=100):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_host, str(ip)): str(ip) for ip in ipaddress.IPv4Network(subnet)}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error scanning {futures[future]}: {e}")
    return results

# API Calls

def post_to_backend(ip, open_ports):
    try:
        payload = {
            "ip": ip,
            "open_ports": open_ports
        }
        r = requests.post(f"{API_BASE}/devices/discovered", json=payload, timeout=10)
        
        if r.status_code == 200:
            print(f"Successfully reported device {ip} with ports {open_ports}")
        else:
            print(f"Failed to report {ip}: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"Error posting device {ip}: {e}")

def get_credentials(ip):
    try:
        r = requests.get(f"{API_BASE}/devices/secrets/{ip}", headers=HEADERS)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Error getting credentials for {ip}: {e}")
    return None

def send_config(config):
    try:
        r = requests.post(f"{API_BASE}/devices/submit_config", json=config, timeout=10)
        print(f"Submitted config for {config.get('device_ip')}: {r.status_code}")
        print(f"[DEBUG] Backend response: {r.text}")
    except Exception as e:
        print(f"Failed to submit config for {config.get('device_ip')}: {e}")



def parse_interfaces_combined(brief_output, run_config_lines):
    # First parse show ip int brief
    brief = {}
    lines = brief_output.strip().splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            name = parts[0]
            brief[name] = {
                "name": name,
                "ip_address": parts[1],
                "ok": parts[2],
                "method": parts[3],
                "status": ' '.join(parts[4:-1]),
                "protocol": parts[-1]
            }

    # Now parse running-config interface blocks
    config = defaultdict(dict)
    current_iface = None
    for line in run_config_lines:
        line = line.strip()
        if line.startswith("interface "):
            current_iface = line.split()[1]
        elif current_iface:
            if line.startswith("description"):
                config[current_iface]["description"] = line.replace("description", "").strip()
            elif line.startswith("ip address"):
                ip_info = line.replace("ip address", "").strip()
                config[current_iface]["ip_address_config"] = ip_info
            elif "ip access-group" in line:
                match = re.search(r"ip access-group (\S+) in", line)
                if match:
                    config[current_iface]["access_group_in"] = match.group(1)
            elif "ip nat inside" in line:
                config[current_iface]["nat_enabled"] = True
            elif line == "shutdown":
                config[current_iface]["shutdown"] = True
        if line == "!" and current_iface:
            current_iface = None

    # Merge both sources
    merged = []
    all_interfaces = set(brief.keys()).union(config.keys())
    for iface in all_interfaces:
        data = {}
        data.update(brief.get(iface, {"name": iface}))
        data.update(config.get(iface, {}))
        data.setdefault("shutdown", False)
        data.setdefault("nat_enabled", False)
        merged.append(data)

    return merged

def parse_show_version(output):
    lines = output.strip().splitlines()
    for line in lines:
        # Match IOS XE or IOS classic version strings
        match = re.search(r"(IOS[\- ]XE Software|Cisco IOS Software).+Version ([\d\.]+)", line)
        if match:
            return {
                "ios_type": match.group(1),
                "version": match.group(2)
            }
    return {"error": "Version not found"}

def parse_show_ip_route(output):
    routes = []
    lines = output.strip().splitlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Gateway") or line.startswith("Codes:"):
            continue

        try:
            parts = line.split()
            protocol = parts[0]
            if protocol == 'S*':  # special case for default static route
                protocol = 'S'

            if "is directly connected" in line:
                network = parts[1]
                iface = parts[-1]
                routes.append({
                    "protocol": protocol,
                    "network": network,
                    "interface": iface
                })

            elif "via" in line:
                network = parts[1]
                metric = parts[2]
                next_hop = parts[4].rstrip(",")
                iface = parts[-1]
                routes.append({
                    "protocol": protocol,
                    "network": network,
                    "metric": metric,
                    "next_hop": next_hop,
                    "interface": iface
                })
        except Exception as e:
            routes.append({"error": f"Failed to parse line: {line}", "details": str(e)})
    return routes

def parse_show_access_lists(output):
    lines = output.strip().splitlines()
    access_lists = []
    current_acl = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # ACL header line
        if line.startswith("Standard IP access list"):
            name = line.split()[-1]
            current_acl = {
                "name": name,
                "type": "standard",
                "entries": []
            }
            access_lists.append(current_acl)

        elif line.startswith("Extended IP access list"):
            name = line.split()[-1]
            current_acl = {
                "name": name,
                "type": "extended",
                "entries": []
            }
            access_lists.append(current_acl)

        # ACL entry line
        elif current_acl and re.match(r"^\d+", line):
            parts = line.split()
            sequence = parts[0]
            action = parts[1]
            remaining = ' '.join(parts[2:])

            entry = {
                "sequence": sequence,
                "action": action,
                "match": remaining
            }

            # Simple split for standard ACL
            if current_acl["type"] == "standard":
                entry["source"] = remaining

            current_acl["entries"].append(entry)

    return access_lists

def parse_running_config_sections(run_config_lines):
    parsed = {
        "vty": [],
        "console": [],
        "aux": [],
        "snmp": [],
        "services": [],
        "aaa": [],
        "enable": {}
    }
    parsed["usernames"] = []
    current_section = None
    buffer = []

    for line in run_config_lines:
        stripped = line.strip()

        # Skip banners and unnecessary lines
        if stripped.startswith("banner") or stripped in {"!", "end", ""}:
            if current_section and buffer:
                if current_section in ["vty", "console", "aux"]:
                    parsed[current_section].append(buffer)
                buffer = []
                current_section = None
            continue

        # Section start detection
        if stripped.startswith("line vty"):
            if buffer and current_section:
                parsed[current_section].append(buffer)
            current_section = "vty"
            buffer = [stripped]
            continue

        elif stripped.startswith("line con"):
            if buffer and current_section == "vty":
                parsed[current_section].append(buffer)
            current_section = "console"
            buffer = [stripped]
            continue

        elif stripped.startswith("line aux"):
            if buffer and current_section == "console":
                parsed[current_section].append(buffer)
            current_section = "aux"
            buffer = [stripped]
            continue

        elif stripped.startswith("snmp-server"):
            parsed["snmp"].append(stripped)
            continue

        elif stripped.startswith("service"):
            parsed["services"].append(stripped)
            continue

        elif stripped.startswith("aaa "):
            parsed["aaa"].append(stripped)
            continue

        elif stripped.startswith("username "):
            parsed["usernames"].append(stripped)

        elif stripped.startswith("enable secret") or stripped.startswith("enable password"):
            parts = stripped.split()
            parsed["enable"]["type"] = parts[1]
            parsed["enable"]["value"] = ' '.join(parts[2:])
            continue

        # Add config lines to section buffer
        if current_section:
            buffer.append(stripped)

    # Final section flush
    if current_section and buffer:
        if current_section in ["vty", "console", "aux"]:
            parsed[current_section].append(buffer)

    parsed["nat"] = extract_nat_rules(run_config_lines)

    return parsed

def extract_nat_rules(run_config_lines):
    nat_rules = []

    for line in run_config_lines:
        line = line.strip()
        if line.startswith("ip nat inside source list"):
            match = re.match(r"ip nat inside source list (\S+) interface (\S+)( overload)?", line)
            if match:
                rule = {
                    "type": "dynamic_nat" if match.group(3) else "static_nat",
                    "acl": match.group(1),
                    "interface": match.group(2),
                    "overload": bool(match.group(3))
                }
                nat_rules.append(rule)
    return nat_rules

def extract_interface_modes(raw_lines):
    modes = {}
    current_iface = None

    for line in raw_lines:
        line = line.strip()
        if line.startswith("interface "):
            current_iface = line.split()[1]
        elif line.startswith("switchport mode") and current_iface:
            mode = line.split()[-1]
            modes[current_iface] = mode
    return modes

def parse_cdp_neighbors(output):
    neighbors = {}
    blocks = output.split("Device ID:")

    for block in blocks[1:]:
        lines = block.strip().splitlines()
        if not lines:
            continue
        device_id = lines[0].strip()
        local_intf = ""
        remote_intf = ""

        for line in lines:
            if "Interface:" in line and "Port ID" in line:
                match = re.search(r'Interface:\s+(\S+),.*Port ID.*:\s+(\S+)', line)
                if match:
                    local_intf, remote_intf = match.groups()
                    neighbors[local_intf] = {
                        "device_id": device_id,
                        "port_id": remote_intf
                    }
    return neighbors

def collect_config(device):
    conn = ConnectHandler(**device)
    conn.enable()
    config_json = {
        "device_ip": device["host"],
        "collected_at": datetime.utcnow().isoformat(),
        "sections": {}
    }

    raw_outputs = {}
    for section, cmd in commands.items():
        try:
            raw_output = conn.send_command(cmd)
            raw_outputs[section] = raw_output
        except Exception as e:
            raw_outputs[section] = f"Error: {str(e)}"

    conn.disconnect()

    for section, raw_output in raw_outputs.items():
        try:
            if section == "raw_config":
                parsed = raw_output.strip().splitlines()
                config_json["sections"]["raw_config"] = parsed
            elif section == "interfaces":
                brief_output = raw_output
                run_config_lines = config_json["sections"].get("raw_config", [])
                parsed = parse_interfaces_combined(brief_output, run_config_lines)
            elif section == "version":
                parsed = parse_show_version(raw_output)
            elif section == "routes":
                parsed = parse_show_ip_route(raw_output)
            elif section == "access_lists":
                parsed = parse_show_access_lists(raw_output)
            else:
                parsed = raw_output.strip().splitlines()
            config_json["sections"][section] = parsed
        except Exception as e:
            config_json["sections"][section] = f"Error: {str(e)}"

    config_json["sections"]["parsed_config"] = parse_running_config_sections(
        config_json["sections"].get("raw_config", [])
    )
    # Only delete raw_config if parsed_config is valid
    #if config_json["sections"].get("parsed_config"):
        #del config_json["sections"]["raw_config"]

    # Enhance interfaces with mode + CDP neighbor info
    raw_lines = config_json["sections"].get("raw_config", [])
    modes = extract_interface_modes(raw_lines)

    # Fix: convert list to string before parsing CDP
    cdp_raw = config_json["sections"].get("cdp_neighbors", [])
    cdp_output = "\n".join(cdp_raw) if isinstance(cdp_raw, list) else cdp_raw
    cdp_neighbors = parse_cdp_neighbors(cdp_output)

    for iface in config_json["sections"].get("interfaces", []):
        name = iface.get("name")
        if name:
            iface["mode"] = modes.get(name, "unknown")
            if name in cdp_neighbors:
                iface["cdp_neighbor"] = cdp_neighbors[name]

def is_known_device(ip):
    headers = {
        "Authorization": f"Bearer {AGENT_TOKEN}"
    }
    try:
        r = requests.get(f"{API_BASE}/devices/secrets/{ip}", headers=headers, timeout=10)
        return r.status_code == 200
    except Exception as e:
        print(f"Error checking if device {ip} is known: {e}")
        return False

def summarize_results(devices):
    print("\n[Scan Summary]")
    if not devices:
        print("No devices found.")
    for device in devices:
        ports = ", ".join(str(p) for p in device["open_ports"]) or "No open ports"
        print(f" - {device['ip']}: Open Ports -> {ports}")

def map_protocol_to_device_type(protocol):
    mapping = {
        "ssh": "cisco_ios",
        "telnet": "cisco_ios",
    }
    return mapping.get(protocol, "cisco_ios")
        
def main():
    init_sqlite()
    discovered = discover_hosts(SUBNET)

    for device in discovered:
        post_to_backend(device['ip'], device['open_ports'])

    summarize_results(discovered)

    for device in discovered:
        ip = device["ip"]
        open_ports = device["open_ports"]
        
        if is_known_device(ip):
            print(f"Known device {ip}, attempting config collection.")
            creds = get_credentials(ip)
            if creds:
                device = {
                    "device_type": map_protocol_to_device_type(creds.get("protocol")),
                    "host": ip,
                    "username": creds.get("username"),
                    "password": creds.get("password"),
                    "secret": creds.get("password"),
                }
                print(f"[DEBUG] Using Netmiko device_type: {device['device_type']} for {ip}")
                config = collect_config(device)
                print(f"[DEBUG] Section keys: {list(config['sections'].keys())}")
                with open(f"debug_config_{config['device_ip']}.json", "w") as f:
                    json.dump(config, f, indent=2)
                send_config(config)
        else:
            print(f"Unknown device {ip}, skipping config collection.")

if __name__ == "__main__":
    main()


