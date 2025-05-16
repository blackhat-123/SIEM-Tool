import time
import os
import sys

# List of suspicious keywords to monitor
suspicious_keywords = [
    "failed login",
    "unauthorized access",
    "error",
    "attack",
    "root access",
    "malware",
    "sql injection",
    "xss attempt"
]

def watch_log(file_path):
    print(f"[+] Monitoring '{file_path}' for suspicious activity...\n")
    try:
        with open(file_path, 'r') as file:
            file.seek(0, os.SEEK_END)  # Move to end of file for real-time monitoring

            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                for keyword in suspicious_keywords:
                    if keyword.lower() in line.lower():
                        print(f"[ALERT] Suspicious log entry detected: {line.strip()}")

    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python dogwatch.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]

    if not os.path.exists(log_file):
        print(f"[!] Log file '{log_file}' not found.")
        sys.exit(1)

    watch_log(log_file)

if __name__ == "__main__":
    main()
