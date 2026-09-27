"""Tier-1 tests for provider-aware response summarisers (pure)."""

from __future__ import annotations

from app.intel.live_enrichment import summarize_response


def test_virustotal_file_stats():
    body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 4, "timeout": 0},
                "tags": ["peexe", "trojan"],
                "reputation": -12,
            }
        }
    }
    s = summarize_response("virustotal", body)
    assert s["detections"] == "5 / 70"
    assert s["malicious"] == 5
    assert s["tags"] == ["peexe", "trojan"]


def test_abuseipdb():
    body = {"data": {"abuseConfidenceScore": 88, "totalReports": 42, "countryCode": "RU", "isp": "EvilCorp"}}
    s = summarize_response("abuseipdb", body)
    assert s["abuse_score"] == 88
    assert s["reports"] == 42
    assert s["country"] == "RU"


def test_shodan():
    body = {"ports": [22, 443, 8080], "org": "Acme", "hostnames": ["x.example.com"], "os": "Linux"}
    s = summarize_response("shodan", body)
    assert s["open_ports"] == [22, 443, 8080]
    assert s["org"] == "Acme"
    assert s["hostnames"] == ["x.example.com"]


def test_urlscan_search():
    body = {"total": 3, "results": [{"task": {"url": "http://bad.example"}, "verdicts": {"overall": {"score": 80}}}]}
    s = summarize_response("urlscan", body)
    assert s["total_results"] == 3


def test_unknown_provider_marks_raw_available():
    s = summarize_response("custom-thing", {"whatever": 1})
    assert s == {"raw_available": True}


def test_none_provider_marks_raw_available():
    assert summarize_response(None, {"x": 1}) == {"raw_available": True}


def test_defensive_against_missing_keys():
    # Malformed/empty bodies must not raise.
    assert isinstance(summarize_response("virustotal", {}), dict)
    assert isinstance(summarize_response("abuseipdb", {"data": {}}), dict)
    assert isinstance(summarize_response("shodan", {}), dict)
    assert isinstance(summarize_response("urlscan", {}), dict)
    assert isinstance(summarize_response("virustotal", {"data": "notadict"}), dict)


# ── Derived verdict (graph node colouring) ─────────────────────────────────


def _verdict(provider, summary):
    from app.intel.live_enrichment import ENRICHMENT_VERDICTS, verdict_from_summary

    return ENRICHMENT_VERDICTS[verdict_from_summary(provider, summary)]


def test_virustotal_verdict_thresholds():
    assert _verdict("virustotal", {"detections": "9 / 70", "malicious": 9, "suspicious": 0}) == "malicious"
    assert _verdict("virustotal", {"detections": "1 / 70", "malicious": 1, "suspicious": 0}) == "suspicious"
    assert _verdict("virustotal", {"detections": "0 / 70", "malicious": 0, "suspicious": 2}) == "suspicious"
    assert _verdict("virustotal", {"detections": "0 / 70", "malicious": 0, "suspicious": 0}) == "clean"


def test_virustotal_without_stats_has_no_verdict():
    """No `detections` means we never got last_analysis_stats — that is not 'clean'."""
    assert _verdict("virustotal", {"tags": ["peexe"]}) == "none"


def test_abuseipdb_verdict_thresholds():
    assert _verdict("abuseipdb", {"abuse_score": 90}) == "malicious"
    assert _verdict("abuseipdb", {"abuse_score": 50}) == "malicious"
    assert _verdict("abuseipdb", {"abuse_score": 30}) == "suspicious"
    assert _verdict("abuseipdb", {"abuse_score": 0}) == "clean"
    assert _verdict("abuseipdb", {"reports": 3}) == "none"


def test_facts_are_not_verdicts():
    """Open ports and a scan count are facts. Painting a node red for answering on 443
    would be worse than painting nothing, so these providers get no verdict at all."""
    assert _verdict("shodan", {"open_ports": [22, 443, 3389], "org": "Example"}) == "none"
    assert _verdict("urlscan", {"total_results": 12}) == "none"
    assert _verdict("some-custom-service", {"raw_available": True}) == "none"


def test_verdict_never_raises_on_junk():
    from app.intel.live_enrichment import verdict_from_summary

    for junk in (None, "text", 5, [], {"malicious": "many"}):
        assert verdict_from_summary("virustotal", junk) == 0
    assert verdict_from_summary(None, {"malicious": 9}) == 0
