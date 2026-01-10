import re #regex
from datetime import datetime, timedelta


failed_login_counter = {}
failed_login_user = {}

alerted_keys = set()
source = "windows"


def detect_windows_bruteforce(event):

    if event["source"] != "windows":
        return
    
    if event["event_id"] != "4625":
        return
    
    ip = event["ip"]
    event_time = datetime.fromisoformat(event["timestamp"].replace("Z",""))

    
    failed_login_counter.setdefault(ip,[]).append(event_time)

    #Window Checker
    window = timedelta(minutes=5)
    failed_login_counter[ip] = [
        t for t in failed_login_counter[ip] 
        if event_time - t < window
    ]

    unique_users = {event["username"] for _ in failed_login_counter[ip]}

    if len(failed_login_counter[ip]) >= 5 and ip not in alerted_keys:
        
        severity = "HIGH" if len(unique_users) > 1 else "MEDIUM"
        alerted_keys.add(ip)

        print(f"\n[{severity}] Windows Brute Force Detected")
        print(f"IP Address: {ip}")
        print(f"Username: {event['username']}")
        print(f"Attempts: {len(failed_login_counter[ip])}\n")

def detect_windows_password_spraying(event):
    if event["source"] != "windows":
        return
    
    if event["event_id"] != "4625":
        return
    
    username = event["username"]
    ip = event["ip"]
    
    event_time = datetime.fromisoformat(event["timestamp"].replace("Z",""))

    failed_login_user.setdefault(username, []).append((ip, event_time))

    window = timedelta(minutes=3)
    failed_login_user[username] = [
        (i,t) for (i,t) in failed_login_user[username]
        if event_time - t < window
    ]

    unique_ips = {i for (i, _) in failed_login_user[username]}
    if len(unique_ips) >= 3 and username not in alerted_keys:

        alerted_keys.add(username)
        print("[HIGH] Windows Password Spraying Detected")
        print(f"Targeted Username : {username}")
        print(f"Unique IPs        : {len(unique_ips)}")
        print(f"Time Window       : {window}\n")

def normalize_timestamp(ts):
    dt = datetime.strptime(ts, "%m/%d/%Y %H:%M:%S")
    return dt.isoformat() + "Z"
    print(dt)

def parse_windows_log(line):
    pattern = (
        r"(?P<timestamp>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) " 
        r"EventID:(?P<event_id>\d+) " 
        r"AccountName:(?P<username>\w+) " 
        r"SourceIP:(?P<ip>[\d\.]+) " 
        r"LogonType:(?P<logon_type>\d+)"
    )

    match = re.search(pattern,line)

    if match:
        return match.groupdict()
    return None

def run_detections(event):
    detect_windows_bruteforce(event)
    detect_windows_password_spraying(event)


with open(r"logs\windowsLogs.txt","r") as logText:
    for line in logText:
        parsed = parse_windows_log(line.strip())
        
        if parsed:
            parsed["timestamp"] = normalize_timestamp(parsed["timestamp"])
            parsed["source"] = "windows"
            run_detections(parsed)
        else:
            print("Unparsed Event")
