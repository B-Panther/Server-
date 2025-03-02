import os
import sys
import uuid
import time
import hashlib
import requests
import subprocess
import re

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Symbols
SUCCESS = "✅"
FAILURE = "❌"
INFO = "ℹ️"
WARNING = "⚠️"

# GitHub URLs
APPROVAL_URL = "https://raw.githubusercontent.com/technicalarslan22/Server-Ali/main/Approval.txt"
KEY_HASH_URL = f"https://raw.githubusercontent.com/technicalarslan22/Server-Ali/main/key_hash.txt?t={int(time.time())}"

# File storage path
SD_CARD_PATH = "/sdcard/unique_key.txt"

# Security constants
MAX_RETRIES = 3
RETRY_DELAY = 2

def fetch_data(url: str) -> str:
    """Fetches data from a URL with retries on failure."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.text.strip()
        except requests.RequestException as e:
            print(f"{FAILURE} {RED}Attempt {attempt}: Failed to fetch {url} - {e}{RESET}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            else:
                print(f"{FAILURE} {RED}Max retries reached. Exiting.{RESET}")
                sys.exit(1)

def get_unique_key() -> str:
    """Generates or retrieves a unique key for the user."""
    try:
        if os.path.exists(SD_CARD_PATH):
            with open(SD_CARD_PATH, "r") as f:
                return f.read().strip()

        unique_key = str(uuid.uuid4())
        with open(SD_CARD_PATH, "w") as f:
            f.write(unique_key)

        print(f"{SUCCESS} {GREEN}Generated new unique key: {unique_key}{RESET}")
        return unique_key
    except Exception as e:
        print(f"{FAILURE} {RED}Error handling unique key: {e}{RESET}")
        sys.exit(1)

def calculate_file_hash(file_path: str) -> str:
    """Calculates the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"{FAILURE} {RED}Error calculating file hash: {e}{RESET}")
        sys.exit(1)

def validate_key_hash() -> bool:
    """Validates the script's hash against the one on GitHub."""
    github_hash = fetch_data(KEY_HASH_URL)
    script_hash = calculate_file_hash(os.path.realpath(__file__))

    print(f"{INFO} {CYAN}GitHub Key Hash: {github_hash}{RESET}")
    print(f"{INFO} {CYAN}Current Script Hash: {script_hash}{RESET}")

    if script_hash != github_hash:
        print(f"{FAILURE} {RED}Hash mismatch! Possible modification detected. Exiting...{RESET}")
        sys.exit(1)
    return True

def is_key_approved(key: str) -> bool:
    """Checks if the key is approved from GitHub."""
    approval_list = fetch_data(APPROVAL_URL).split("\n")
    if key in approval_list:
        print(f"{SUCCESS} {GREEN}Key is approved! Proceeding...{RESET}")
        return True

    print(f"{FAILURE} {RED}Key not approved. Request access from the admin.{RESET}")
    print(f"{INFO} {CYAN}Your Key: {key}{RESET}")
    
    wa_message = f"https://wa.me/+923049211464?text=Hello%20Sir!%20Please%20Approve%20My%20Token:%20{key}"
    print(f"{INFO} {CYAN}Send approval request here: {wa_message}{RESET}")
    
    try:
        subprocess.run(["termux-open-url", wa_message])
    except Exception:
        pass  # Ignore if Termux is unavailable

    sys.exit(1)

def is_device_rooted() -> bool:
    """Detects if the device is rooted."""
    root_files = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
        "/sbin/magisk", "/data/adb/magisk"
    ]
    if any(os.path.exists(file) for file in root_files):
        print(f"{WARNING} {YELLOW}Root access detected! Exiting...{RESET}")
        sys.exit(1)
    return False

def is_network_monitoring_detected() -> bool:
    """Detects network monitoring tools running on the device."""
    try:
        processes = subprocess.run(["ps"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = processes.stdout.decode('utf-8').lower()
        
        for tool in ["httpcanary", "pcapdroid", "wireshark", "fiddler", "charles"]:
            if tool in output:
                print(f"{WARNING} {YELLOW}Network monitoring tool detected: {tool}. Exiting...{RESET}")
                sys.exit(1)
    except Exception as e:
        print(f"{FAILURE} {RED}Error checking for network monitoring tools: {e}{RESET}")
        sys.exit(1)
    return False

def main():
    """Main function to run the approval system."""
    print(f"{INFO} {CYAN}Starting Secure Key Approval System...{RESET}")

    # Security Checks
    is_device_rooted()
    is_network_monitoring_detected()

    # Key Approval
    unique_key = get_unique_key()
    ####validate_key_hash()
    is_key_approved(unique_key)

if __name__ == "__main__":
    main()
