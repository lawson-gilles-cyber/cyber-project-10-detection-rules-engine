# Detection Rules Engine (SIEM Simulation)

# Sample logs
logs = [
    "LOGIN FAILED - admin - 45.33.32.1",
    "LOGIN FAILED - admin - 45.33.32.1",
    "LOGIN FAILED - admin - 45.33.32.1",
    "LOGIN SUCCESS - admin - 45.33.32.1",
    "FILE ACCESS - confidential.docx"
]

# Threshold for brute force detection
THRESHOLD = 3

# Store failed attempts per IP
failed_attempts = {}

# Store alerts
alerts = []

# Process logs
for log in logs:
    parts = log.split(" - ")
    event = parts[0]

    # Rule 1: Detect brute force attempts
    if event == "LOGIN FAILED":
        ip = parts[2]

        if ip not in failed_attempts:
            failed_attempts[ip] = 0

        failed_attempts[ip] += 1

        # Trigger alert when threshold reached
        if failed_attempts[ip] == THRESHOLD:
            alerts.append(f"[RULE] Brute force detected from {ip}")

    # Rule 2: Detect suspicious login
    elif event == "LOGIN SUCCESS":
        ip = parts[2]

        if ip in failed_attempts and failed_attempts[ip] >= THRESHOLD:
            alerts.append(f"[RULE] Suspicious login from {ip}")

    # Rule 3: Detect sensitive file access
    elif event == "FILE ACCESS":
        file = parts[1]
        alerts.append(f"[RULE] Sensitive file accessed: {file}")

# Output results
print("=== Detection Engine Report ===\n")

for alert in alerts:
    print(alert)
