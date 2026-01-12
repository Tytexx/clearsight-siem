import re #regex
from datetime import datetime, timedelta
import json
import os
import uuid


failed_login_counter = {}
failed_login_user = {}
last_alert_time = {}

source = "windows"

ALERT_SUPPRESSION = timedelta(minutes=10)
STATE_FILE = "siem_state.json"



#Helper functions for iso-date conversion
def dt_to_str(dt):
    return datetime.isoformat(dt)

def str_to_dt(str):
    return datetime.fromisoformat(str)

def serialize_state(): #Seralize for saving to .json file
    return {
        "failed_login_counter": {
            ip: [(u, dt_to_str(t)) for (u, t) in attempts]
            for ip, attempts in failed_login_counter.items()
        },
        "failed_login_user": {
            user: [(ip, dt_to_str(t)) for (ip, t) in attempts]
            for user, attempts in failed_login_user.items()
        },
        "last_alert_time": {
            key: dt_to_str(t)
            for key, t in last_alert_time.items()
        }
    }

def save_state():
    with open(STATE_FILE, "w") as f:
        json.dump(serialize_state(), f, indent=2)



def should_emit_alert(event, key):
        now = datetime.fromisoformat(event["timestamp"].replace("Z",""))
        if key in last_alert_time:
            if now - last_alert_time[key] < ALERT_SUPPRESSION:
                return False 
            
        last_alert_time[key] = now
        return True

def load_state():
    if not os.path.exists(STATE_FILE):
        return
    
    with open (STATE_FILE,"r") as f:
        data = json.load(f)

    failed_login_counter.clear()
    failed_login_user.clear()
    last_alert_time.clear()

    for ip, attempts in data.get("failed_login_counter", {}).items():
        failed_login_counter[ip] = [(u, str_to_dt(t)) for (u, t) in attempts]

    for user, attempts in data.get("failed_login_user", {}).items():
        failed_login_user[user] = [(ip, str_to_dt(t)) for (ip, t) in attempts]

    for key, t in data.get("last_alert_time", {}).items():
        last_alert_time[key] = str_to_dt(t)        


def detect_windows_bruteforce(event):

    if event["source"] != "windows":
        return
    
    if event["event_id"] != "4625":
        return
    
    ip = event["ip"]
    event_time = datetime.fromisoformat(event["timestamp"].replace("Z",""))

    
    failed_login_counter.setdefault(ip, []).append((event["username"], event_time))
    #Window Checker
    window = timedelta(minutes=5)
    failed_login_counter[ip] = [
        (u,t) for (u,t) in failed_login_counter[ip] 
        if event_time - t < window
    ]

    unique_users = {u for (u,_) in failed_login_counter[ip]}
    if len(failed_login_counter[ip]) >= 5 and ip:
        
        severity = "HIGH" if len(unique_users) > 1 else "MEDIUM"

        alert = {
            "Severity": severity,               
            "Title": "Windows Brute Force Detected",
            "Source": event["source"],            
            "IP Address": ip,
            "Username": event["username"],
            "Attempts": len(failed_login_counter.get(ip, [])),  
            "Time Window": "5 minutes",         
            "Timestamp": event["timestamp"],
            "rule_id": "WIN-BRUTE-001"
        }

        if should_emit_alert(event, ip):
            emit_alert(alert)

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
    if len(unique_ips) >= 3 and username:

        alert = {
            "Severity": "HIGH",               
            "Title": "Windows Password Spraying Detected",
            "Source": event["source"],            
            "IP Address": ip,
            "Username": event["username"],
            "Attempts": len(failed_login_user.get(username, [])),  
            "Time Window": "3 minutes",         
            "Timestamp": event["timestamp"],
            "rule_id": "WIN-SPRAY-002"

        }

        if should_emit_alert(event, username):
            emit_alert(alert)

def normalize_timestamp(ts):
    dt = datetime.strptime(ts, "%m/%d/%Y %H:%M:%S")
    return dt.isoformat() + "Z"
    print(dt)

def emit_alert(alert):
    alert["alert_id"] = str(uuid.uuid4())
    print("\n ALERT")
    for k,v in alert.items():
        print(f"{k}: {v}")
    with open("alerts.json","a") as f:
        f.write(json.dumps(alert) + "\n")

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

DETECTIONS = [
    detect_windows_bruteforce,
    detect_windows_password_spraying
]

def run_detections(event):
    for detection in DETECTIONS:
            detection(event)


with open(r"logs\windowsLogs.txt","r") as logText:
    load_state()
    for line in logText:
        parsed = parse_windows_log(line.strip())
        
        if parsed:
            parsed["timestamp"] = normalize_timestamp(parsed["timestamp"])
            parsed["source"] = "windows"
            run_detections(parsed)
            save_state()
        else:
            print("Unparsed Event")

