import argparse
import csv
import ipaddress
import json
import os
import subprocess
import uuid

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests


# --------------------------------------------------
# DEFAULT CONFIGURATION
# --------------------------------------------------

DEFAULT_INTERFACE = "eth1"
DEFAULT_DURATION = 100
DEFAULT_THRESHOLD = 40
DEFAULT_DESTINATION_IP = "192.168.10.10"

PCAP_FILE = Path("traffic.pcap")
CSV_FILE = Path("traffic.csv")
ALERT_FILE = Path("alert.json")


# --------------------------------------------------
# COMMAND EXECUTION
# --------------------------------------------------

def run_command(command, description, timeout=None, stdout=None):
    print(f"[+] {description}")

    try:
        return subprocess.run(
            command,
            check=True,
            timeout=timeout,
            stdout=stdout,
            stderr=subprocess.PIPE,
            text=True
        )

    except FileNotFoundError:
        raise RuntimeError(
            f"Required program not found: {command[0]}"
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError("The command timed out.")

    except subprocess.CalledProcessError as error:
        details = error.stderr or "No additional error details."
        raise RuntimeError(f"Command failed: {details}")


# --------------------------------------------------
# STEP 1: CAPTURE NETWORK TRAFFIC
# --------------------------------------------------

def capture_traffic(interface, destination_ip, duration):

    if PCAP_FILE.exists():
        PCAP_FILE.unlink()

    capture_filter = f"icmp and dst host {destination_ip}"

    command = [
        "tshark",
        "-n",
        "-i", interface,
        "-f", capture_filter,
        "-a", f"duration:{duration}",
        "-w", str(PCAP_FILE)
    ]

    run_command(
        command,
        f"Capturing ICMP traffic on {interface} "
        f"for {duration} seconds",
        timeout=duration + 30
    )

    if not PCAP_FILE.exists() or PCAP_FILE.stat().st_size == 0:
        raise RuntimeError("No usable packet capture was created.")

    print(f"[+] PCAP saved: {PCAP_FILE}")


# --------------------------------------------------
# STEP 2: CONVERT PCAP TO CSV
# --------------------------------------------------

def convert_to_csv():

    if CSV_FILE.exists():
        CSV_FILE.unlink()

    command = [
        "tshark",
        "-r", str(PCAP_FILE),
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f"
    ]

    with CSV_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as output:

        run_command(
            command,
            "Converting PCAP metadata to CSV",
            stdout=output
        )

    print(f"[+] CSV saved: {CSV_FILE}")


# --------------------------------------------------
# STEP 3: ANALYZE TRAFFIC
# --------------------------------------------------

def analyze_traffic(threshold):

    statistics = defaultdict(
        lambda: {
            "packet_count": 0,
            "total_bytes": 0,
            "first_seen": None,
            "last_seen": None
        }
    )

    total_packets = 0

    with CSV_FILE.open(
        "r", newline="", encoding="utf-8"
    ) as csvfile:

        reader = csv.DictReader(csvfile)

        required_fields = {
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "ip.proto",
            "frame.len"
        }

        if not reader.fieldnames or not required_fields.issubset(
            set(reader.fieldnames)
        ):
            raise RuntimeError("CSV is missing expected fields.")

        for row in reader:

            source_ip = (row.get("ip.src") or "").strip()
            timestamp = (row.get("frame.time_epoch") or "").strip()
            packet_length = (row.get("frame.len") or "").strip()

            if not source_ip:
                continue

            try:
                packet_time = float(timestamp)
                packet_bytes = int(packet_length)
            except (ValueError, TypeError):
                continue

            record = statistics[source_ip]

            record["packet_count"] += 1
            record["total_bytes"] += packet_bytes
            total_packets += 1

            if record["first_seen"] is None:
                record["first_seen"] = packet_time

            record["last_seen"] = packet_time

    findings = []

    print("\n[+] Traffic volume by source IP:\n")

    for source_ip, record in sorted(
        statistics.items(),
        key=lambda item: item[1]["packet_count"],
        reverse=True
    ):

        print(
            f"{source_ip}: {record['packet_count']} packets, "
            f"{record['total_bytes']} bytes"
        )

        if record["packet_count"] >= threshold:

            findings.append({
                "source_ip": source_ip,
                "packet_count": record["packet_count"],
                "total_bytes": record["total_bytes"],
                "first_seen_utc": datetime.fromtimestamp(
                    record["first_seen"], timezone.utc
                ).isoformat(),
                "last_seen_utc": datetime.fromtimestamp(
                    record["last_seen"], timezone.utc
                ).isoformat()
            })

    print(f"\n[+] Total packets analyzed: {total_packets}")
    print(f"[+] Source IPs analyzed: {len(statistics)}")
    print(f"[+] Detection threshold: {threshold}")

    return findings, total_packets


# --------------------------------------------------
# STEP 4: GENERATE JSON ALERT
# --------------------------------------------------

def generate_alert(
    findings,
    total_packets,
    interface,
    destination_ip,
    duration,
    threshold
):

    alert = {
        "alert_id": f"SOC-{uuid.uuid4().hex[:8].upper()}",

        "alert_type": "High-Volume ICMP Traffic",

        "severity": "Medium",

        "status": "Requires Analyst Review",

        "detection": {
            "threshold_packets": threshold,
            "capture_duration_seconds": duration,
            "protocol": "ICMP",
            "destination_ip": destination_ip
        },

        "sensor": {
            "interface": interface
        },

        "evidence": {
            "total_packets_analyzed": total_packets,
            "suspicious_source_count": len(findings),
            "pcap_file": PCAP_FILE.name,
            "csv_file": CSV_FILE.name
        },

        "findings": findings,

        "analyst_question": (
            "Is this ICMP traffic expected, or could it indicate "
            "network scanning, monitoring activity, or unusual behavior?"
        ),

        "generated_at_utc": datetime.now(timezone.utc).isoformat()
    }

    with ALERT_FILE.open("w", encoding="utf-8") as output:
        json.dump(alert, output, indent=4)

    print(f"\n[+] Alert saved: {ALERT_FILE}")

    return alert


# --------------------------------------------------
# STEP 5: OPTIONAL AIRIA INTEGRATION
# --------------------------------------------------

def send_to_airia(alert):

    api_url = os.getenv("AIRIA_API_URL")
    api_key = os.getenv("AIRIA_API_KEY")

    if not api_url or not api_key:
        raise RuntimeError(
            "Configure AIRIA_API_URL and AIRIA_API_KEY first."
        )

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": api_key
    }

    # Verify this payload and authentication format
    # against your actual Airia agent API documentation.

    payload = {
        "userInput": json.dumps(alert),
        "asyncOutput": False
    }

    print("[+] Sending alert to Airia...")

    try:
        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=(10, 60)
        )

        response.raise_for_status()

    except requests.RequestException as error:
        raise RuntimeError(f"Airia request failed: {error}")

    print(f"[+] Airia HTTP status: {response.status_code}")

    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text[:4000])


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="SOC Network Traffic Monitoring and Alerting"
    )

    parser.add_argument(
        "--interface",
        default=DEFAULT_INTERFACE
    )

    parser.add_argument(
        "--destination",
        default=DEFAULT_DESTINATION_IP
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD
    )

    parser.add_argument(
        "--send",
        action="store_true",
        help="Send the alert to Airia"
    )

    args = parser.parse_args()

    if args.duration <= 0 or args.threshold <= 0:
        parser.error("Duration and threshold must be positive.")

    try:
        destination = ipaddress.ip_address(args.destination)

        if destination.version != 4:
            parser.error("Only IPv4 destinations are supported.")

    except ValueError:
        parser.error("Invalid destination IP address.")

    try:

        capture_traffic(
            args.interface,
            str(destination),
            args.duration
        )

        convert_to_csv()

        findings, total_packets = analyze_traffic(
            args.threshold
        )

        if not findings:
            print("\n[+] No source IP met the threshold.")
            print("[+] No alert generated.")
            return

        alert = generate_alert(
            findings,
            total_packets,
            args.interface,
            str(destination),
            args.duration,
            args.threshold
        )

        if args.send:
            send_to_airia(alert)
        else:
            print(
                "[+] Local testing mode: alert saved locally. "
                "Nothing was sent to Airia."
            )

        print("\n[+] Monitoring workflow completed.")

    except (RuntimeError, OSError) as error:
        print(f"\n[!] ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
