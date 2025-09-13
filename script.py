#!/usr/bin/env python3

import requests
import json
import argparse
import validators
import sys
import concurrent.futures
import itertools

from argparse import RawTextHelpFormatter

requests.packages.urllib3.disable_warnings()

# --- CONFIGURATION ---
try:
    with open('config.json') as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    print("[!] CRITICAL: 'config.json' not found. Please create it with your Acunetix URL, port, and API key.")
    sys.exit(1)
except json.JSONDecodeError:
    print("[!] CRITICAL: 'config.json' is not valid JSON.")
    sys.exit(1)

# Dictionary mapping short aliases to official Acunetix profile names
PROFILE_ALIASES = {
    "full": "Full Scan",
    "high": "Critical / High Risk",
    "medium": "Critical / High / Medium Risk",
    "xss": "Cross-site Scripting",
    "sql": "SQL Injection",
    "weakpass": "Weak Passwords",
    "crawl": "Crawl Only",
    "owasp": "OWASP Top 10",
    "pci": "PCI checks",
    "without": "Without Top 25",
    "malware": "Malware Scan"
}

tarurl = config['url']+":"+str(config['port'])
headers = {
    "X-Auth": config['api_key'],
    "Content-Type": "application/json"
}

# --- PROXY FUNCTION ---
def load_and_parse_proxies(file_path="proxy.txt"):
    parsed_proxies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':')
                proxy_config = {"enabled": True, "protocol": "http"}
                
                if len(parts) == 2:
                    proxy_config["address"] = parts[0]
                    proxy_config["port"] = int(parts[1])
                elif len(parts) == 4:
                    proxy_config["username"] = parts[0]
                    proxy_config["password"] = parts[1]
                    proxy_config["address"] = parts[2]
                    proxy_config["port"] = int(parts[3])
                else:
                    print(f"[!] Skipping invalid proxy format in {file_path}: {line}")
                    continue
                parsed_proxies.append(proxy_config)

        if parsed_proxies:
            print(f"[*] Successfully loaded and parsed {len(parsed_proxies)} proxies from {file_path}.")
        else:
            print(f"[!] Warning: Proxy file '{file_path}' was found but contained no valid proxies.")
            
    except FileNotFoundError:
        print(f"[!] Warning: Proxy file '{file_path}' not found. Scans will run without proxies.")
    except (ValueError, IndexError) as e:
        print(f"[!] Error parsing proxy file: {e}. Please check the format.")

    return parsed_proxies


# --- API FUNCTIONS ---
def get_scan_profiles():
    url = f"{tarurl}/api/v1/scanning_profiles"
    try:
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        profiles_data = response.json()
        
        if isinstance(profiles_data, dict) and "scanning_profiles" in profiles_data:
            profiles_list = profiles_data["scanning_profiles"]
        else:
            print("[!] Unexpected API response format. Could not find 'scanning_profiles' key.")
            return {}

        return {profile['name']: profile['profile_id'] for profile in profiles_list}

    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching scan profiles: {e}")
        return {}
    except (KeyError, json.JSONDecodeError) as e:
        print(f"[!] Error parsing scan profiles: {e}")
        return {}

def list_profiles():
    print("[*] Fetching available scan profiles...")
    profiles = get_scan_profiles()
    if not profiles:
        print("[!] No scan profiles found or could not connect to API.")
        return
    
    alias_lookup = {v: k for k, v in PROFILE_ALIASES.items()}
    
    print("\n--- Available Scan Profiles ---")
    for name, profile_id in profiles.items():
        alias = alias_lookup.get(name, "N/A")
        print(f"- Alias: \"{alias}\"\n  Name:  \"{name}\"\n  ID:    {profile_id}\n")
    print("-----------------------------\n")
    print("Use the 'Alias' or the full 'Name' in the -t/--type argument.")


def create_scan(target_url, scan_type, speed, user_agent, scan_profiles, proxy_config=None):
    profile_id = scan_profiles.get(scan_type)

    if not profile_id:
        print(f"[!] Scan profile '{scan_type}' not found. Attempting to use 'Full Scan' as default.")
        profile_id = scan_profiles.get(PROFILE_ALIASES.get("full"))
        if not profile_id:
            print(f"\n[!] CRITICAL: Default profile 'Full Scan' also not found. Aborting scan for {target_url}.")
            print("[*] Available profiles are:", ", ".join(f'"{p}"' for p in scan_profiles.keys()))
            return

    def add_and_configure_target(url, speed_setting, ua_string, default_profile_id, proxy_settings):
        create_data = {"address": url, "description": url, "criticality": 10}
        target_id = None
        try:
            response = requests.post(f"{tarurl}/api/v1/targets", data=json.dumps(create_data), headers=headers, timeout=30, verify=False)
            response.raise_for_status()
            target_id = response.json()['target_id']
            print(f"[*] Target created for {url} with ID: {target_id}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error adding target {url}: {e}")
            return None

        config_data = {'default_scanning_profile_id': default_profile_id}
        if speed_setting: config_data['scan_speed'] = speed_setting
        if ua_string: config_data['user_agent'] = ua_string
        if proxy_settings:
            config_data['proxy'] = proxy_settings
            print(f"[*] Assigning proxy {proxy_settings['address']}:{proxy_settings['port']} to {url}")


        if target_id:
            config_url = f"{tarurl}/api/v1/targets/{target_id}/configuration"
            try:
                print(f"[*] Applying configuration to target {target_id}...")
                response = requests.patch(config_url, data=json.dumps(config_data), headers=headers, timeout=30, verify=False)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"[!] Warning: Failed to apply configuration for {url}. Error: {e}")
        
        return target_id

    target_id = add_and_configure_target(target_url, speed, user_agent, profile_id, proxy_config)
    if not target_id:
        print(f"[!] Failed to create target for {target_url}. Aborting scan.")
        return

    scan_data = {
        "target_id": target_id,
        "profile_id": profile_id,
        "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
    }

    try:
        actual_profile_name = next((name for name, pid in scan_profiles.items() if pid == profile_id), "Unknown")
        response = requests.post(f"{tarurl}/api/v1/scans", headers=headers, data=json.dumps(scan_data), verify=False, timeout=30)
        response.raise_for_status()
        print(f"[*] Scan successfully launched for {target_url} using profile '{actual_profile_name}'.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error launching scan for {target_url}: {e}")


def scan_targets_from_file(file_path, scan_type, speed, user_agent, scan_profiles, proxies=None):
    try:
        with open(file_path) as f:
            targets = [x.strip() for x in f.readlines() if x.strip()]
        
        valid_targets = []
        for target in targets:
            if not target.startswith(("http://", "https://")): target = "https://" + target
            if validators.url(target):
                valid_targets.append(target)
            else:
                print(f"[!] Skipping invalid URL from file: {target}")

        if not valid_targets:
            print("[!] No valid URLs found in the file.")
            return

        print(f"[*] Found {len(valid_targets)} valid targets. Starting scans...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            if proxies:
                proxy_cycler = itertools.cycle(proxies)
                futures = {executor.submit(create_scan, target, scan_type, speed, user_agent, scan_profiles, next(proxy_cycler)): target for target in valid_targets}
            else:
                futures = {executor.submit(create_scan, target, scan_type, speed, user_agent, scan_profiles, None): target for target in valid_targets}
            
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] An exception occurred while processing {target}: {e}")

    except FileNotFoundError:
        print(f"[!] Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"[!] An unexpected error occurred while reading the file: {e}")

def stop_scan(scan_id):
    url = f"{tarurl}/api/v1/scans/{scan_id}/abort"
    try:
        requests.post(url, headers=headers, verify=False, timeout=60)
        print(f"[-] Abort request sent for scan ID: {scan_id}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to stop scan {scan_id}. Error: {e}")

def stop_specific_scan(target):
    try:
        url = f"{tarurl}/api/v1/scans?q=status:processing,queued;target_address:{target}"
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        scans = response.json()["scans"]
        if not scans:
            print(f"[!] No active or queued scan found for target: {target}")
            return
        for scan in scans:
            print(f"[*] Found active scan for '{target}'. ID: {scan['scan_id']}")
            stop_scan(scan["scan_id"])
    except requests.exceptions.RequestException as e:
        print(f"[!] Error retrieving scans to stop. Error: {e}")

def stop_all_scans():
    print("[*] Attempting to stop all active and queued scans...")
    try:
        url = f"{tarurl}/api/v1/scans?q=status:processing,queued"
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        scans = response.json().get("scans", [])
        if not scans:
            print("[*] No active or queued scans found to stop.")
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(stop_scan, [scan['scan_id'] for scan in scans])
        print(f"[+] Total abort requests sent: {len(scans)}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Network error while fetching scans: {e}")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    banner = r"""
                      __  _         ___
  ____ ________  ____  ___  / /_(_)   __  _____/ (_)
 / __ `/ ___/ / / / __ \/ _ \/ __/ / |/_/_____/ ___/ / /
/ /_/ / /__/ /_/ / / / /  __/ /_/ />  </_____/ /__/ / / 
\__,_/\___/\__,_/_/ /_/\___/\__/_/|_|       \___/_/_/   
 -:  by EvilWhales x CFS :-
    """
    
    profile_choices = ", ".join(PROFILE_ALIASES.keys())
    
    parser = argparse.ArgumentParser(
        description="""
AcuAutomate: Unofficial Acunetix CLI
------------------------------------
A command-line tool to automate Acunetix vulnerability scans.
It allows you to start, stop, and manage scans directly from your terminal,
making it perfect for integration into CI/CD pipelines or batch scanning operations.
""",
        epilog=f"""
Commands & Options:
---------------------------------------------------------------------------------------------
scan                     ▶ Launch a new scan. Requires one of -d or -f.

  -d, --domain DOMAIN    A single target domain to scan (e.g., example.com).
  -f, --file FILE        A file with target domains, one per line.
  -t, --type TYPE        Scan profile alias. (Default: full)
                           Choices: {{ {profile_choices} }}
  -s, --speed SPEED      Set scan speed. Choices: {{ slow, moderate, fast, faster }}
  -u, --user-agent UA    Set a custom User-Agent for the scan.
  -p, --proxy            Enable proxies for the scan. Requires a 'proxy.txt' file.
                           Create 'proxy.txt' and add proxies one per line.
                           Format (no auth):    ip:port
                           Format (with auth):  user:pass:ip:port

---------------------------------------------------------------------------------------------
stop                     ⏹ Stop a scan. Requires one of -d or -a.

  -d, --domain DOMAIN    The target domain of the scan to stop.
  -a, --all              Stop ALL running and queued scans.

---------------------------------------------------------------------------------------------
list-profiles            📋 List all available scan profiles and their aliases.

---------------------------------------------------------------------------------------------
Examples:
------------------------------------
# List all available scan profiles
  python3 AcuAutomate.py list-profiles

# Start a specific 'SQL Injection' scan on a single target
  python3 AcuAutomate.py scan -d example.com -t sql

# Start a full scan for all targets in 'links.txt' using a proxy for each one
  python3 AcuAutomate.py scan -f links.txt --proxy
 
# Start an advanced scan on multiple targets that bypasses WAF and acts like a real human ( you can include --proxy if you have proxy in your proxy.txt file / 1 per line - it will assign different proxy to targets from file in ip:port format or user:pass:ip:port format )
 python3 AcuAutomate.py scan -f links.txt -s slow -u "Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/20100101 Firefox/10.0" -t high

# Stop an active scan for a specific domain
  python3 AcuAutomate.py stop -d example.com
""",
        formatter_class=RawTextHelpFormatter
    )
    
    if len(sys.argv) < 2:
        print(banner)
        parser.print_help()
        sys.exit(1)
        
    print(banner)
    
    subparsers = parser.add_subparsers(dest="action", required=True)
    
    # --- SCAN SUBPARSER ---
    start_parser = subparsers.add_parser("scan", help=argparse.SUPPRESS)
    start_group = start_parser.add_mutually_exclusive_group(required=True)
    start_group.add_argument("-d", "--domain", help="A single target domain")
    start_group.add_argument("-f", "--file", help="A file with target domains")
    start_parser.add_argument("-t", "--type", default="full", help="Scan profile alias")
    start_parser.add_argument("-s", "--speed", choices=['slow', 'moderate', 'fast', 'faster'], help="Scan speed")
    start_parser.add_argument("-u", "--user-agent", help="Custom User-Agent")
    start_parser.add_argument("-p", "--proxy", action="store_true", help="Use proxies from proxy.txt for the scan engine")
    
    # --- STOP SUBPARSER ---
    stop_parser = subparsers.add_parser("stop", help=argparse.SUPPRESS)
    stop_group = stop_parser.add_mutually_exclusive_group(required=True)
    stop_group.add_argument("-d", "--domain", help="The target domain of the scan to stop")
    stop_group.add_argument("-a", "--all", action='store_true', help="Stop ALL scans")

    # --- LIST PROFILES SUBPARSER ---
    list_parser = subparsers.add_parser("list-profiles", help=argparse.SUPPRESS)
    
    args = parser.parse_args()
    
    scan_profile_name = PROFILE_ALIASES.get(args.type.lower(), args.type) if hasattr(args, 'type') else None
    
    if args.action == "list-profiles":
        list_profiles()
        
    elif args.action == "scan":
        proxies = load_and_parse_proxies() if args.proxy else []
        
        print("[*] Getting scan profiles from Acunetix...")
        scan_profiles = get_scan_profiles()
        if not scan_profiles:
            print("[!] CRITICAL: Could not retrieve scan profiles from Acunetix. Aborting.")
            sys.exit(1)

        if args.domain:
            target_url = args.domain
            if not target_url.startswith(("http://", "https://")): target_url = "https://" + target_url
            if validators.url(target_url):
                first_proxy = proxies[0] if proxies else None
                create_scan(target_url, scan_profile_name, args.speed, args.user_agent, scan_profiles, first_proxy)
            else:
                print(f"[!] Invalid URL specified: {args.domain}")
        elif args.file:
            scan_targets_from_file(args.file, scan_profile_name, args.speed, args.user_agent, scan_profiles, proxies)
            
    elif args.action == "stop":
        if args.domain: stop_specific_scan(args.domain)
        elif args.all: stop_all_scans()