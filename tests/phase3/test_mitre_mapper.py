from agent.mitre.mapper import map_to_mitre


def test_log4shell_maps_to_t1190():
    findings = {
        "cve_findings": {"description": "JNDI RCE via log4shell"},
        "graph_findings": {"reachable_from_internet": True, "hop_count": 3},
    }
    techniques = map_to_mitre(findings)
    ids = [t["technique_id"] for t in techniques]
    assert "T1190" in ids


def test_rce_maps_to_execution():
    findings = {
        "cve_findings": {"description": "Remote code execution via arbitrary code"},
        "graph_findings": {"reachable_from_internet": False},
    }
    techniques = map_to_mitre(findings)
    ids = [t["technique_id"] for t in techniques]
    assert "T1059" in ids or "T1203" in ids


def test_no_findings_returns_empty():
    techniques = map_to_mitre({})
    assert techniques == []
