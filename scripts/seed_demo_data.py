"""
Simulates realistic traffic — normal background noise PLUS a brute-force
burst, a port scan, and a suspicious-process event — against a running
instance of the API. This is what a reviewer / HR person runs to see the
whole system light up with alerts in under a minute.

Usage:
    python scripts/seed_demo_data.py [--base-url http://localhost:8000]
"""
import argparse
import random
import time

import httpx

NORMAL_IPS = ["192.168.1.10", "192.168.1.14", "192.168.1.22"]
ATTACKER_IP = "203.0.113.55"
SCANNER_IP = "198.51.100.23"


def send(client: httpx.Client, api_key: str, event: dict):
    resp = client.post("/ingest", headers={"x-api-key": api_key}, json=event)
    resp.raise_for_status()
    return resp.json()


def main(base_url: str, api_key: str):
    with httpx.Client(base_url=base_url, timeout=10) as client:
        print(f"Checking API health at {base_url} ...")
        client.get("/health").raise_for_status()

        print("Sending normal background traffic ...")
        for _ in range(15):
            ip = random.choice(NORMAL_IPS)
            send(client, api_key, {
                "source": "host-normal",
                "event_type": random.choice(["login_success", "file_access", "connection_attempt"]),
                "source_ip": ip,
                "destination_port": random.choice([443, 80, 22]),
                "username": "svc_account",
                "message": "routine activity",
            })

        print("Simulating brute-force login attack from", ATTACKER_IP, "...")
        for i in range(8):
            result = send(client, api_key, {
                "source": "auth-server",
                "event_type": "login_failed",
                "source_ip": ATTACKER_IP,
                "username": f"admin{i}",
                "message": "invalid credentials",
            })
        print("  -> alerts triggered on final request:", result["alerts_triggered"])

        print("Simulating port scan from", SCANNER_IP, "...")
        for port in [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 8080]:
            result = send(client, api_key, {
                "source": "edge-firewall",
                "event_type": "connection_attempt",
                "source_ip": SCANNER_IP,
                "destination_port": port,
                "message": f"SYN to port {port}",
            })
        print("  -> alerts triggered on final request:", result["alerts_triggered"])

        print("Simulating suspicious process execution ...")
        result = send(client, api_key, {
            "source": "workstation-07",
            "event_type": "process_start",
            "source_ip": "192.168.1.44",
            "username": "jdoe",
            "message": "cmd.exe spawned mimikatz.exe with args -privesc",
        })
        print("  -> alerts triggered:", result["alerts_triggered"])

        print("\nDone. Log in and check GET /alerts to see everything that fired.")
        print("Try the anomaly scan too: POST /alerts/scan-anomalies (admin token required).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--api-key", default="dev-ingest-key-change-me")
    args = parser.parse_args()
    main(args.base_url, args.api_key)
