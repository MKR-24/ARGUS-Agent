"""
ARGUS — Autonomous Security Investigation Agent
Streamlit demo interface with live reasoning trace.
"""

import base64
import json

import requests
import streamlit as st

API_URL = "http://localhost:8080"

st.set_page_config(
    page_title="ARGUS — Security Investigation Agent",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 ARGUS")
st.caption(
    "Autonomous Security Investigation Agent — Multi-agent CVE analysis with MITRE ATT&CK mapping"
)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Benchmark Scorecard")
    st.metric("Task Completion", "100%", delta="↑ vs 75% target")
    st.metric("Hallucination Rate", "0.0%", delta="↓ better")
    st.metric("Injection Hijack Rate", "0.0%", delta="↓ better")
    st.metric("Tool Accuracy", "84.1%")
    st.metric("Avg MTTI", "18.9s")
    st.divider()
    st.caption("30-alert benchmark · 10 real · 10 synthetic · 10 adversarial")
    st.link_button(
        "🔗 View Braintrust Scorecard",
        "https://www.braintrust.dev/app/PERSONAL_AGENT/p/ARGUS-Agent",
    )

# ── Alert form ────────────────────────────────────────────────────────────────
st.header("Submit Security Alert")

col1, col2 = st.columns(2)

with col1:
    alert_id = st.text_input("Alert ID", value="ALERT-DEMO-001")
    service_id = st.selectbox(
        "Affected Service",
        [
            "user-svc",
            "payment-svc",
            "auth-svc",
            "order-svc",
            "api-gw",
            "inventory-svc",
            "notify-svc",
            "report-svc",
            "admin-svc",
            "pg-main",
            "lb-01",
        ],
    )
    cve_id = st.text_input("CVE ID (optional)", value="CVE-2021-44228")

with col2:
    scanner = st.selectbox("Scanner", ["trivy", "grype", "checkov", "snyk"])
    severity_raw = st.selectbox(
        "Scanner Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )
    description = st.text_area(
        "Description",
        value="Trivy detected Log4Shell vulnerability in user-svc container image. "
        "Apache Log4j2 JNDI RCE vulnerability.",
        height=100,
    )

# Image upload
st.subheader("Visual Evidence (optional)")
uploaded_files = st.file_uploader(
    "Upload screenshots (dashboards, SIEM panels, packet captures)",
    type=["png", "jpg", "jpeg"],
    accept_multiple_files=True,
    help="Max 5 images, 5MB each. VLM will extract security indicators.",
)

evidence_images = []
if uploaded_files:
    for f in uploaded_files[:5]:
        img_b64 = base64.b64encode(f.read()).decode()
        evidence_images.append(img_b64)
    st.success(f"{len(evidence_images)} image(s) attached")

# ── Investigation ─────────────────────────────────────────────────────────────

if st.button("🚀 Investigate Alert", type="primary", use_container_width=True):
    st.divider()
    st.header("Investigation Trace")
    payload = {
        "alert_id": alert_id,
        "service_id": service_id,
        "cve_id": cve_id.strip() if cve_id.strip() else None,
        "scanner": scanner,
        "severity_raw": severity_raw,
        "description": description,
        "evidence_images": evidence_images,
    }

    # Start investigation and get stream URL
    init_resp = requests.post(f"{API_URL}/alerts/investigate/stream", json=payload)
    init_resp.raise_for_status()
    alert_id = init_resp.json()["alert_id"]
    stream_url = f"{API_URL}/alerts/{alert_id}/events"

    report = None
    elapsed = 0.0
    trace_placeholder = st.empty()
    trace_lines = []
    event_type = ""
    with requests.get(stream_url, stream=True, timeout=120) as sse_resp:
        for line in sse_resp.iter_lines():
            if not line:
                continue
            line = line.decode("utf-8")

            if line.startswith("event:"):
                event_type = line.split(":", 1)[1].strip()

            if line.startswith("data:"):
                data = json.loads(line.split(":", 1)[1].strip())

                if event_type == "agent_start":
                    trace_lines.append(
                        f"{data.get('icon', '🔵')} **{data['agent']}** — {data['message']}"
                    )
                elif event_type == "agent_complete":
                    trace_lines.append(f"   ✅ {data['message']}")
                elif event_type == "hitl_pending":
                    st.warning(
                        f"⚠️ CRITICAL alert requires human approval. "
                        f"Resume via API: POST /alerts/{data['alert_id']}/resume"
                    )
                    st.stop()
                elif event_type == "complete":
                    report = data["report"]
                    elapsed = report.get("mean_time_to_investigate_seconds", 0)
                    trace_lines.append("✅ **Investigation complete**")
                elif event_type == "error":
                    st.error(f"Investigation failed: {data['message']}")
                    st.stop()

                # Update trace display in real time
                trace_placeholder.markdown("\n\n".join(trace_lines))

    if report:
        # ── Report display ────────────────────────────────────────────────────────
        st.header("Incident Report")

        # Severity banner
        severity = report.get("severity", "UNKNOWN")
        severity_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFORMATIONAL": "⚪",
        }
        icon = severity_colors.get(severity, "⚪")
        st.subheader(f"{icon} Severity: {severity}")

        # Key metrics row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("CVSS Score", report.get("cvss_score") or "N/A")
        m2.metric(
            "EPSS Score",
            f"{report.get('epss_score', 0):.1%}" if report.get("epss_score") else "N/A",
        )
        m3.metric(
            "Internet Reachable",
            "Yes" if report.get("reachable_from_internet") else "No",
        )
        m4.metric(
            "Confidence", f"{(report.get('confidence') or {}).get('overall', 0):.0%}"
        )

        # Summary
        st.info(report.get("summary", "No summary available"))

        # Two column layout for details
        left, right = st.columns(2)

        with left:
            st.subheader("Attack Path")
            paths = report.get("attack_paths", [])
            if paths:
                path_str = " → ".join(paths[0])
                st.code(path_str)
                st.caption(f"Hop count: {report.get('hop_count')}")
            else:
                st.caption("No internet-reachable path found")

            st.subheader("Remediation Steps")
            for i, step in enumerate(report.get("remediation", []), 1):
                st.write(f"{i}. {step}")

            st.subheader("Historical Exposure")
            st.metric(
                "Prior findings",
                report.get("prior_exposure_count", 0),
                delta=f"{report.get('unresolved_prior', 0)} unresolved",
                delta_color="inverse",
            )

        with right:
            st.subheader("MITRE ATT&CK Techniques")
            tags = report.get("mitre_attack_tags", [])
            if tags:
                for tag in tags:
                    with st.expander(
                        f"**{tag['technique_id']}** — {tag['technique_name']}"
                    ):
                        st.write(f"**Tactic:** {tag['tactic']}")
                        st.write(f"**Reference:** [{tag['url']}]({tag['url']})")
            else:
                st.caption("No MITRE techniques mapped")

            st.subheader("Confidence Breakdown")
            conf = report.get("confidence") or {}
            if conf:
                st.progress(
                    conf.get("cve_data", 0),
                    text=f"CVE data: {conf.get('cve_data', 0):.0%}",
                )
                st.progress(
                    conf.get("graph_data", 0),
                    text=f"Graph data: {conf.get('graph_data', 0):.0%}",
                )
                st.progress(
                    conf.get("history_data", 0),
                    text=f"History data: {conf.get('history_data', 0):.0%}",
                )
                st.metric("Overall", f"{conf.get('overall', 0):.0%}")

            # Visual findings (if images were uploaded)
            visual = report.get("visual_findings")
            if visual and not visual.get("skipped"):
                st.subheader("👁️ Visual Evidence Findings")
                st.write(f"**Risk signal:** {visual.get('overall_risk_signal')}")
                st.write(visual.get("analyst_note"))
                findings = visual.get("findings", [])
                for f in findings:
                    with st.expander(
                        f"Image: {f.get('evidence_type')} — {f.get('severity_signal') or 'No signal'}"
                    ):
                        st.write(f"**Summary:** {f.get('summary')}")
                        indicators = f.get("indicators", [])
                        if indicators:
                            st.write("**Indicators:**")
                            for ind in indicators:
                                st.write(f"  • {ind}")

        # CVE Description
        if report.get("cve_description"):
            with st.expander("CVE Description"):
                st.write(report["cve_description"])

        # Raw JSON
        with st.expander("Raw Report JSON"):
            st.json(report)

        # MTTI
        st.caption(
            f"Mean time to investigate: {elapsed:.1f}s · Report version: {report.get('report_version')}"
        )
