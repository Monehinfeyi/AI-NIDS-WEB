import os, time, subprocess, platform
from datetime import datetime, timedelta

# --- CONFIGURATION ---
BLOCK_DURATION_HOURS = 24
# Change these paths:
LOG_PATH = "data/threat_log.csv"
BANNED_IPS_DB = "data/banned_ips.txt"
def unblock_ip(ip):
    """Removes the IP from the OS Firewall."""
    os_type = platform.system()
    try:
        if os_type == "Windows":
            rule_name = f"NIDS_BLOCK_{ip}"
            subprocess.run(f"netsh advfirewall firewall delete rule name={rule_name}", shell=True)
        else:
            subprocess.run(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True)
        print(f"🔓 Amnesty: Unblocked {ip}")
    except Exception as e:
        print(f"Error unblocking {ip}: {e}")

def run_janitor():
    while True:
        print(f"[{datetime.now()}] Running Maintenance...")
        
        # 1. IP Amnesty Logic
        if os.path.exists(BANNED_IPS_DB):
            remaining_ips = []
            with open(BANNED_IPS_DB, "r") as f:
                lines = f.readlines()
            
            for line in lines:
                ip, ban_time_str = line.strip().split(",")
                ban_time = datetime.strptime(ban_time_str, "%Y-%m-%d %H:%M:%S")
                
                # Check if 24 hours have passed
                if datetime.now() > ban_time + timedelta(hours=BLOCK_DURATION_HOURS):
                    unblock_ip(ip)
                else:
                    remaining_ips.append(line)
            
            # Update the DB with IPs that are still banned
            with open(BANNED_IPS_DB, "w") as f:
                f.writelines(remaining_ips)

        # 2. Log Cleanup (Optional: Keep only last 10MB)
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 10 * 1024 * 1024:
            os.rename(LOG_PATH, f"{LOG_PATH}.old")
            print("🧹 Logs rotated.")

        # Wait 1 hour before next check
        time.sleep(3600)

if __name__ == "__main__":
    run_janitor()