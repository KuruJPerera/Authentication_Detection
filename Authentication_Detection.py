import json
import re
import datetime
from collections import defaultdict

# Mock IP-to-country mapping (you can expand or source this from your firewall, internal DNS, etc.)
IP_COUNTRY_LOOKUP = {
    "192.168.1.5": "United States",  # john's location
    "10.0.0.2": "Germany",           # alice's location
    "83.244.23.11": "Russia",        # unauthorized
}

# Approved countries per user
APPROVED_LOCATIONS = {
    "john": ["United States"],
    "alice": ["Germany"],
}

FAILED_LOGIN_THRESHOLD = 3

def get_country(ip):
    return IP_COUNTRY_LOOKUP.get(ip, "Unknown")

def parse_log_line(line):
    pattern = r'(?P<datetime>[\d\-]+\s[\d:]+)\sIP=(?P<ip>[\d.]+)\sUSER=(?P<user>\w+)\sACTION=(?P<action>\w+)'
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

# Reads each log line, extracts the important info, keeps track of failures and successes

def analyze_log(file_path):
    results = []
    failed_attempts = defaultdict(int)
    user_ip_actions = defaultdict(list)
    login_success_ips = set()

    with open(file_path, 'r') as f:
        for line in f:
            entry = parse_log_line(line.strip())
            if not entry:
                continue

            ip = entry['ip']
            user = entry['user']
            action = entry['action']
            country = get_country(ip)

            user_ip_actions[(user, ip)].append(action)

            if action == "LOGIN_FAIL":
                failed_attempts[(user, ip)] += 1

            elif action == "LOGIN_SUCCESS":
                login_success_ips.add((user, ip))
                if country not in APPROVED_LOCATIONS.get(user, []):
                    results.append({
                        "user": user,
                        "ip": ip,
                        "country": country,
                        "issue": "Login from unapproved location",
                        "actions": user_ip_actions[(user, ip)]
                    })

    # Evaluate brute force or excessive failure attempts and then records the attributes of the user 
    for (user, ip), count in failed_attempts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            country = get_country(ip)
            results.append({
                "user": user,
                "ip": ip,
                "country": country,
                "issue": f"{count} failed login attempts",
                "actions": user_ip_actions.get((user, ip), [])
            })

    return results

# This function creates a nicely named report file of suspicious login activity, saves it in JSON format, and tells you where to find it with date and time logged to it.

def save_results(results):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"Unauth_Access_{timestamp}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    log_file = "access.log"
    results = analyze_log(log_file)
    if results:
        save_results(results)
    else:
        print("No unauthorized access detected.")
