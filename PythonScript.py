import csv
from collections import defaultdict
import re

# Constants
FAILED_LOGIN_THRESHOLD = 10  # Threshold for failed login attempts


def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regular expressions
    ip_regex = r'(\d+\.\d+\.\d+\.\d+)'  # Match IP address
    endpoint_regex = r'"(?:GET|POST)\s(/[^ ]+)'  # Match endpoint from GET/POST requests
    failed_login_regex = r'HTTP/1\.1" 401'  # Detect 401 Unauthorized or failed login

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.match(ip_regex, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(endpoint_regex, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Detect failed login attempts
            if re.search(failed_login_regex, line):
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins


def detect_suspicious_activity(failed_logins):
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips


def save_results_to_csv(ip_requests, endpoint_requests, suspicious_activity):
    with open('log_analysis_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write IP Request Counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1], default=(None, 0))
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def print_results(ip_requests, endpoint_requests, suspicious_activity):
    # Print IP Request Counts
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:20} {count}")

    # Print Most Accessed Endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1], default=(None, 0))
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Print Suspicious Activity
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:20} {count}")
    else:
        print("\nNo Suspicious Activity Detected.")


def main(log_file_path):
    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file_path)

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(failed_logins)

    # Print results to the console
    print_results(ip_requests, endpoint_requests, suspicious_activity)

    # Save results to CSV file
    save_results_to_csv(ip_requests, endpoint_requests, suspicious_activity)


if __name__ == "__main__":
    log_file_path = "sample.log"  # Path to the log file
    main(log_file_path)
