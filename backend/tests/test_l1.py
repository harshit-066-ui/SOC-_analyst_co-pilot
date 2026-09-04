"""L1 module tests."""

import json
from pathlib import Path

import pytest

from l1.pipeline import L1Pipeline
from l1.adapters import detect_source, get_adapter
from l1.deduplication.fingerprint import deduplicate_events
from l1.normalization.schema_validator import validate_event

TEST_DATA = Path(__file__).resolve().parent.parent.parent / "test_data"


@pytest.fixture
def pipeline(tmp_path):
    return L1Pipeline(output_dir=tmp_path / "output")


class TestAdapters:
    def test_wazuh_detection(self):
        event = {"rule": {}, "agent": {}, "full_log": "test"}
        platform, conf = detect_source([event])
        assert platform == "wazuh"

    def test_suricata_detection(self):
        event = {"event_type": "alert", "flow_id": 123, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "alert": {}}
        platform, conf = detect_source([event])
        assert platform == "suricata"

    def test_firewall_detection(self):
        event = {"action": "block", "interface": "WAN", "src": "1.1.1.1", "dst": "2.2.2.2", "src_port": "80", "dst_port": "443", "protocol": "tcp"}
        platform, conf = detect_source([event])
        assert platform == "firewall"

    def test_wazuh_normalization(self):
        event = {
            "timestamp": "2026-08-18T08:15:22.000Z",
            "rule": {"level": 10, "description": "SSH failed"},
            "agent": {"name": "web-01"},
            "data": {"srcip": "203.0.113.45"},
            "full_log": "Failed password",
        }
        adapter = get_adapter("wazuh")
        normalized = adapter.normalize(event, 1)
        valid, errors = validate_event(normalized)
        assert valid, errors
        assert normalized["source_platform"] == "wazuh"
        assert normalized["source"]["ip"] == "203.0.113.45"


class TestDeduplication:
    def test_removes_duplicates(self):
        events = [
            {"timestamp": "t1", "source_platform": "wazuh", "event_type": "alert", "source": {"ip": "1.1.1.1"}, "destination": {"ip": "2.2.2.2"}, "message": "same"},
            {"timestamp": "t1", "source_platform": "wazuh", "event_type": "alert", "source": {"ip": "1.1.1.1"}, "destination": {"ip": "2.2.2.2"}, "message": "same"},
        ]
        unique, dupes = deduplicate_events(events)
        assert len(unique) == 1
        assert dupes == 1


def _get_test_data(name: str) -> tuple[bytes, str]:
    """Retrieve test data from current_demo or root test_data."""
    mapping = {
        "sample_wazuh.json": "current_demo/wazuh_incident.json",
        "sample_suricata.json": "current_demo/suricata_incident.json",
        "sample_firewall.json": "current_demo/firewall_incident.json",
    }
    candidate = TEST_DATA / mapping.get(name, name)
    if not candidate.exists():
        candidate = TEST_DATA / name
    if candidate.exists():
        return candidate.read_bytes(), candidate.name
    # Fallback minimal synthetic content if file is absent
    synthetic = {
        "sample_mixed.csv": b"timestamp,source_ip,message\n2026-08-18T08:00:00Z,10.0.0.1,test",
        "sample_logs.log": b"2026-08-18T08:00:00Z web-01 sshd: test event",
    }
    return synthetic.get(name, b"[]"), name


class TestPipeline:
    def test_wazuh_file(self, pipeline):
        content, name = _get_test_data("sample_wazuh.json")
        result = pipeline.process_file(content, name)
        report = result["report"]
        assert report["source_detected"] == "wazuh"
        assert report["total_events"] >= 1
        assert report["successfully_normalized"] >= 1
        assert Path(result["output_paths"]["normalized_json"]).exists()

    def test_suricata_file(self, pipeline):
        content, name = _get_test_data("sample_suricata.json")
        result = pipeline.process_file(content, name)
        assert result["report"]["source_detected"] == "suricata"
        assert result["report"]["total_events"] >= 1

    def test_firewall_file(self, pipeline):
        content, name = _get_test_data("sample_firewall.json")
        result = pipeline.process_file(content, name)
        assert result["report"]["source_detected"] == "firewall"
        assert result["report"]["total_events"] >= 1

    def test_paste_json(self, pipeline):
        event = json.dumps({
            "timestamp": "2026-08-18T08:00:00Z",
            "rule": {"level": 5, "description": "test"},
            "agent": {"name": "host1"},
            "full_log": "test event",
        })
        result = pipeline.process_paste(event, source_hint="wazuh")
        assert result["report"]["successfully_normalized"] >= 1

    def test_output_files_created(self, pipeline):
        content, name = _get_test_data("sample_wazuh.json")
        result = pipeline.process_file(content, name)
        for key in ("normalized_json", "normalized_jsonl", "report", "errors"):
            assert Path(result["output_paths"][key]).exists()

    def test_no_invented_values(self, pipeline):
        content, name = _get_test_data("sample_firewall.json")
        result = pipeline.process_file(content, name)
        for event in result["events"]:
            assert event["user"]["id"] is None or isinstance(
                event["user"]["id"], str
            )

