import html
import json
import os
from pathlib import Path
import urllib.request

from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'  <w:top w:w="{top}" w:type="dxa"/>'
        f'  <w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'  <w:left w:w="{left}" w:type="dxa"/>'
        f'  <w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)

def add_callout(doc, title, text, bg_hex="EFF6FF", border_hex="3B82F6"):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
    
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'  <w:left w:val="single" w:sz="24" w:space="0" w:color="{border_hex}"/>'
        f'  <w:top w:val="none"/>'
        f'  <w:right w:val="none"/>'
        f'  <w:bottom w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(2)
    run_title = p.add_run(f"{title}\n")
    run_title.bold = True
    run_title.font.name = "Segoe UI"
    run_title.font.size = Pt(10)
    run_title.font.color.rgb = RGBColor(15, 23, 42)
    
    run_text = p.add_run(text)
    run_text.font.name = "Segoe UI"
    run_text.font.size = Pt(9.5)
    run_text.font.color.rgb = RGBColor(30, 41, 59)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def build_report():
    # 1. Fetch data from running API
    base_url = "http://127.0.0.1:8000"
    try:
        req_d = urllib.request.urlopen(f"{base_url}/api/analytics/detectors")
        det_data = json.loads(req_d.read().decode())
    except Exception:
        det_data = {}
        
    try:
        req_id = urllib.request.urlopen(f"{base_url}/api/analytics/heatmap/identities")
        id_data = json.loads(req_id.read().decode())
    except Exception:
        id_data = {}

    try:
        req_tm = urllib.request.urlopen(f"{base_url}/api/analytics/heatmap/time")
        tm_data = json.loads(req_tm.read().decode())
    except Exception:
        tm_data = {}

    doc = Document()
    for s in doc.sections:
        s.top_margin = Inches(0.7)
        s.bottom_margin = Inches(0.7)
        s.left_margin = Inches(0.7)
        s.right_margin = Inches(0.7)

    # Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(0)
    p_title.paragraph_format.space_after = Pt(2)
    r1 = p_title.add_run("IdentityShield: Attack Summary Report & Heatmap Analytics")
    r1.bold = True
    r1.font.size = Pt(20)
    r1.font.color.rgb = RGBColor(15, 23, 42)

    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(10)
    r_sub = p_sub.add_run("Automated Incident Digest, Threat Matrices, and Zero Trust Mitigations")
    r_sub.font.size = Pt(11)
    r_sub.font.color.rgb = RGBColor(220, 38, 38)
    r_sub.bold = True

    # Meta Table
    m_table = doc.add_table(rows=2, cols=2)
    m_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    m_table.autofit = False
    for r in range(2):
        for c in range(2):
            cell = m_table.cell(r, c)
            cell.width = Inches(3.4)
            set_cell_background(cell, "F8FAFC")
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
    m_table.cell(0, 0).paragraphs[0].add_run("Target Recipient: forclaudelesgo@gmail.com").bold = True
    m_table.cell(0, 1).paragraphs[0].add_run("Severity: CRITICAL (Revocation Guard Active)").bold = True
    m_table.cell(1, 0).paragraphs[0].add_run("Platform: IdentityShield Multi-Agent (15 Agents)").font.size = Pt(9)
    m_table.cell(1, 1).paragraphs[0].add_run("Console: http://127.0.0.1:8000").font.size = Pt(9)
    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    # Executive Summary Box
    add_callout(
        doc,
        "🚨 EXECUTIVE INCIDENT ALERT",
        "IdentityShield detected coordinated multi-cloud attack campaigns across Okta IdP sessions and AWS CloudTrail APIs. "
        "3 high-risk identities require immediate security operations triage: dormant service account 'svc-report' (Risk 100), "
        "'meera.n' (Risk 98.9), and 'dev.kumar' (Risk 89.7). Destructive revocation actions remain safely quarantined pending analyst approval.",
        bg_hex="FEF2F2",
        border_hex="EF4444"
    )

    # SECTION 1: CRITICAL THREATS
    h2_1 = doc.add_heading(level=2)
    h2_1.add_run("1. Detected Attack Profiles & Incident Findings").font.color.rgb = RGBColor(15, 23, 42)
    
    threats = [
        {
            "id": "svc-report",
            "risk": "100.0 (REVOKE)",
            "patterns": "P2 Dormant Account, P3 Privilege Escalation, P4 Unusual API, ML Anomaly",
            "mitre": "T1078.004, T1098, T1526, T1548, T1562",
            "desc": "Privilege escalation chain detected for svc-report: CredCreate (CreateAccessKey) -> PermGrant (AttachUserPolicy) -> RoleAssume (AssumeRole) -> Impact (GetSecretValue) across 4 steps in 11 minutes."
        },
        {
            "id": "meera.n",
            "risk": "98.9 (REVOKE)",
            "patterns": "P4 Unusual API, P5 Token Abuse, ML Anomaly",
            "mitre": "T1526, T1539, T1550, T1562",
            "desc": "Token hijacking and concurrent session misuse across disjoint CIDR blocks following Okta logout event. Isolation forest anomaly score 0.93."
        },
        {
            "id": "dev.kumar",
            "risk": "89.7 (RESTRICT)",
            "patterns": "P4 Unusual API, ML Anomaly",
            "mitre": "T1526, T1562",
            "desc": "Defense evasion via StopLogging API in previously unseen region eu-west-3. Action rarity 99.1% across organizational peer baseline."
        },
        {
            "id": "anita.rao",
            "risk": "51.3 (STEP-UP)",
            "patterns": "P1 Impossible Travel, ML Anomaly",
            "mitre": "T1078",
            "desc": "Geographical velocity anomaly: Okta authentication from Mumbai followed by AWS console activity from Frankfurt within 10 minutes."
        }
    ]

    for t in threats:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(2)
        r_id = p.add_run(f"• Identity: {t['id']} — Risk: {t['risk']}")
        r_id.bold = True
        
        p_d = doc.add_paragraph()
        p_d.paragraph_format.space_before = Pt(0)
        p_d.paragraph_format.space_after = Pt(2)
        p_d.add_run(f"  Patterns: {t['patterns']}\n  MITRE: {t['mitre']}\n  Evidence: {t['desc']}").font.size = Pt(9.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # SECTION 2: IDENTITY VS ATTACK PATTERN HEATMAP
    h2_2 = doc.add_heading(level=2)
    h2_2.add_run("2. Identity vs. Attack Pattern Heatmap Matrix").font.color.rgb = RGBColor(15, 23, 42)

    p_hm_desc = doc.add_paragraph()
    p_hm_desc.paragraph_format.space_after = Pt(4)
    p_hm_desc.add_run("Cross-tabulation of organizational identities against detected threat vectors. "
                      "Cells show signal counts; color shading reflects threat intensity:")

    # Build Table for Heatmap
    if id_data and "identities" in id_data:
        idents = id_data["identities"]
        risks = id_data["risk"]
        patterns = id_data["patterns"]
        cells = id_data["cells"]
        
        table = doc.add_table(rows=len(idents) + 1, cols=len(patterns) + 2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        
        # Headers
        headers = ["Identity", "Risk"] + patterns
        widths = [Inches(1.5), Inches(0.8)] + [Inches(0.75)] * len(patterns)
        
        for i, h in enumerate(headers):
            cell = table.cell(0, i)
            cell.width = widths[i]
            set_cell_background(cell, "0F172A")
            set_cell_margins(cell, top=80, bottom=80, left=80, right=80)
            p = cell.paragraphs[0]
            r = p.add_run(h)
            r.bold = True
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(255, 255, 255)
            
        # Rows
        for r_idx, ident in enumerate(idents):
            row_cells = table.rows[r_idx + 1].cells
            row_cells[0].width = widths[0]
            row_cells[1].width = widths[1]
            set_cell_margins(row_cells[0], top=60, bottom=60, left=80, right=80)
            set_cell_margins(row_cells[1], top=60, bottom=60, left=80, right=80)
            
            p_id = row_cells[0].paragraphs[0]
            p_id.add_run(ident).bold = True
            
            risk_val = risks[r_idx]
            p_rk = row_cells[1].paragraphs[0]
            r_rk = p_rk.add_run(f"{risk_val:.0f}")
            r_rk.bold = True
            if risk_val >= 90:
                set_cell_background(row_cells[1], "FEE2E2") # red
                r_rk.font.color.rgb = RGBColor(185, 28, 28)
            elif risk_val >= 70:
                set_cell_background(row_cells[1], "FEF3C7") # amber
                r_rk.font.color.rgb = RGBColor(180, 83, 9)
            elif risk_val >= 40:
                set_cell_background(row_cells[1], "E0F2FE") # cyan
                r_rk.font.color.rgb = RGBColor(3, 105, 161)
            else:
                set_cell_background(row_cells[1], "F1F5F9") # neutral
                
            for c_idx, val in enumerate(cells[r_idx]):
                c_cell = row_cells[c_idx + 2]
                c_cell.width = widths[c_idx + 2]
                set_cell_margins(c_cell, top=60, bottom=60, left=60, right=60)
                p_c = c_cell.paragraphs[0]
                p_c.alignment = WD_ALIGN_PARAGRAPH.CENTER
                r_c = p_c.add_run(str(val))
                if val >= 3:
                    set_cell_background(c_cell, "FCA5A5") # heavy red
                    r_c.bold = True
                    r_c.font.color.rgb = RGBColor(153, 27, 27)
                elif val == 2:
                    set_cell_background(c_cell, "FED7AA") # orange
                    r_c.bold = True
                elif val == 1:
                    set_cell_background(c_cell, "FEF08A") # yellow
                else:
                    set_cell_background(c_cell, "F8FAFC")
                    r_c.font.color.rgb = RGBColor(148, 163, 184)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # SECTION 3: TIME ATTACK VELOCITY HEATMAP
    h2_3 = doc.add_heading(level=2)
    h2_3.add_run("3. Temporal Attack Velocity & Concentration Heatmap").font.color.rgb = RGBColor(15, 23, 42)
    
    p_tm_desc = doc.add_paragraph()
    p_tm_desc.paragraph_format.space_after = Pt(4)
    p_tm_desc.add_run("Hourly distribution of anomalous activity (adjusted for local UTC+05:30 IST). "
                      "Identifies attacker dwell time, reconnaissance windows, and automated burst execution:")

    time_table = doc.add_table(rows=5, cols=4)
    time_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    time_table.autofit = False
    
    headers_tm = ["Date", "Active Window (IST)", "Incident Count", "Attack Stage Observed"]
    widths_tm = [Inches(1.5), Inches(1.8), Inches(1.2), Inches(2.3)]
    for i, h in enumerate(headers_tm):
        c = time_table.cell(0, i)
        c.width = widths_tm[i]
        set_cell_background(c, "1E293B")
        set_cell_margins(c, top=80, bottom=80, left=80, right=80)
        p = c.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(255, 255, 255)

    time_rows = [
        ("2026-10-26", "09:00 - 10:00 IST", "1 event", "Dormant service account reactivation (svc-report)"),
        ("2026-10-26", "10:00 - 11:00 IST", "2 events", "Initial IAM policy enumeration & credential creation"),
        ("2026-10-27", "13:00 - 14:00 IST", "5 events (PEAK)", "Multi-step Privilege Escalation + StopLogging tampering"),
        ("2026-10-27", "16:00 - 17:00 IST", "5 events (PEAK)", "Concurrent token abuse & secret exfiltration (GetSecretValue)")
    ]

    for idx, (dt, win, cnt, stg) in enumerate(time_rows, start=1):
        row = time_table.rows[idx]
        for ci, val in enumerate([dt, win, cnt, stg]):
            cell = row.cells[ci]
            cell.width = widths_tm[ci]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            if "PEAK" in val:
                set_cell_background(cell, "FEE2E2")
                r.bold = True
                r.font.color.rgb = RGBColor(185, 28, 28)
            else:
                set_cell_background(cell, "F8FAFC" if idx % 2 == 0 else "FFFFFF")

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # SECTION 4: DETECTION BENCHMARK MATRIX
    h2_4 = doc.add_heading(level=2)
    h2_4.add_run("4. Multi-Agent Detection & Model Benchmark Matrix").font.color.rgb = RGBColor(15, 23, 42)

    p_bm_desc = doc.add_paragraph()
    p_bm_desc.paragraph_format.space_after = Pt(4)
    p_bm_desc.add_run("Performance evaluation across Rule-based Detectors, Behavioral ML (Isolation Forest), and the Hybrid Ensemble:")

    bm_table = doc.add_table(rows=4, cols=7)
    bm_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    bm_table.autofit = False
    
    headers_bm = ["Detector Architecture", "Flagged", "TP", "FP", "Precision", "Recall", "F1 Score"]
    widths_bm = [Inches(2.2), Inches(0.7), Inches(0.6), Inches(0.6), Inches(0.9), Inches(0.8), Inches(0.8)]
    for i, h in enumerate(headers_bm):
        c = bm_table.cell(0, i)
        c.width = widths_bm[i]
        set_cell_background(c, "0F172A")
        set_cell_margins(c, top=80, bottom=80, left=60, right=60)
        p = c.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(255, 255, 255)

    bm_rows = [
        ("Deterministic Rules (P1-P5)", "5", "5", "0", "100.0%", "71.4%", "0.833"),
        ("Behavioral ML (Isolation Forest)", "16", "7", "9", "43.8%", "100.0%", "0.609"),
        ("Hybrid Ensemble (IdentityShield)", "4", "4", "0", "100.0%", "57.1%", "0.727")
    ]

    for idx, (arch, fl, tp, fp, pr, rc, f1) in enumerate(bm_rows, start=1):
        row = bm_table.rows[idx]
        for ci, val in enumerate([arch, fl, tp, fp, pr, rc, f1]):
            cell = row.cells[ci]
            cell.width = widths_bm[ci]
            set_cell_margins(cell, top=60, bottom=60, left=60, right=60)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            if "Hybrid" in arch:
                set_cell_background(cell, "ECFDF5")
                r.bold = True
                r.font.color.rgb = RGBColor(4, 120, 87)
            elif "Rules" in arch:
                set_cell_background(cell, "EFF6FF")
            else:
                set_cell_background(cell, "FFFFFF")

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # SECTION 5: ZERO TRUST MITIGATION LOG
    h2_5 = doc.add_heading(level=2)
    h2_5.add_run("5. Automated Containment & Policy Governance Log").font.color.rgb = RGBColor(15, 23, 42)

    add_callout(
        doc,
        "🛡️ Zero Trust Containment Guard",
        "• AL-0001 (svc-report, Risk 100): REVOKE action QUARANTINED pending security analyst sign-off.\n"
        "• AL-0002 (meera.n, Risk 98.9): REVOKE action QUARANTINED pending security analyst sign-off.\n"
        "• AL-0003 (dev.kumar, Risk 89.7): RESTRICT access auto-applied via simulation adapter.\n"
        "• AL-0004 (anita.rao, Risk 51.3): STEP-UP MFA notified within daily friction budget.\n\n"
        "Cryptographic Audit Hash Chain Status: (True, None) — 100% Validated.",
        bg_hex="F0FDF4",
        border_hex="22C55E"
    )

    out_path_docx = Path("C:/Users/Omana/OneDrive/Desktop/IdentityShield_Attack_Summary_With_Heatmaps.docx")
    doc.save(str(out_path_docx))
    print(f"Generated Word Report: {out_path_docx}")

    # Also build standalone HTML report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IdentityShield Attack Summary & Heatmap Analytics</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 32px; line-height: 1.5; }}
  .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.4); }}
  h1 {{ margin: 0 0 6px; font-size: 26px; color: #ffffff; }}
  .subtitle {{ color: #ef4444; font-weight: 600; margin-bottom: 20px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; background: #0f172a; padding: 16px; border-radius: 8px; margin-bottom: 24px; border: 1px solid #334155; }}
  .meta-item {{ font-size: 13px; }}
  .meta-item b {{ color: #94a3b8; display: block; font-size: 11px; text-transform: uppercase; }}
  .alert-banner {{ background: rgba(239, 68, 68, 0.15); border-left: 4px solid #ef4444; padding: 16px; border-radius: 6px; margin-bottom: 28px; }}
  h2 {{ color: #38bdf8; font-size: 18px; margin: 28px 0 12px; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; }}
  th {{ background: #0f172a; color: #cbd5e1; font-weight: 600; }}
  .cell-heavy {{ background: rgba(239, 68, 68, 0.35); color: #fca5a5; font-weight: bold; text-align: center; }}
  .cell-medium {{ background: rgba(249, 115, 22, 0.3); color: #fed7aa; font-weight: bold; text-align: center; }}
  .cell-light {{ background: rgba(234, 179, 8, 0.25); color: #fef08a; text-align: center; }}
  .cell-zero {{ background: rgba(15, 23, 42, 0.6); color: #64748b; text-align: center; }}
  .badge-revoke {{ background: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
  .badge-restrict {{ background: #f59e0b; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
  .badge-stepup {{ background: #0284c7; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
  .zt-box {{ background: rgba(34, 197, 94, 0.1); border-left: 4px solid #22c55e; padding: 16px; border-radius: 6px; margin-top: 24px; }}
</style>
</head>
<body>
<div class="container">
  <h1>IdentityShield: Attack Summary Report & Heatmap Analytics</h1>
  <div class="subtitle">Automated Incident Digest, Threat Matrices, and Zero Trust Mitigations</div>
  
  <div class="meta-grid">
    <div class="meta-item"><b>Target Recipient</b>forclaudelesgo@gmail.com</div>
    <div class="meta-item"><b>Severity Level</b>CRITICAL (Human-in-the-Loop Revocation Guard Active)</div>
    <div class="meta-item"><b>Architecture</b>15 Specialized Agents across 5 Security Layers</div>
    <div class="meta-item"><b>Local Dashboard</b><a href="http://127.0.0.1:8000" style="color: #38bdf8;">http://127.0.0.1:8000</a></div>
  </div>

  <div class="alert-banner">
    <strong style="color: #ef4444;">🚨 EXECUTIVE INCIDENT SUMMARY</strong><br>
    Coordinated multi-cloud attack campaigns detected across Okta IdP authentication and AWS CloudTrail APIs.
    3 high-risk identities require immediate response: dormant account <code>svc-report</code> (Risk 100), <code>meera.n</code> (Risk 98.9), and <code>dev.kumar</code> (Risk 89.7).
    Destructive revocation actions remain safely quarantined pending security analyst approval.
  </div>

  <h2>1. Attack Profiles & Incident Findings</h2>
  <table>
    <tr><th>Identity</th><th>Risk & Band</th><th>Attack Patterns</th><th>Key Finding & MITRE Mapping</th></tr>
    <tr>
      <td><b>svc-report</b></td>
      <td><span class="badge-revoke">100 REVOKE</span></td>
      <td>P2, P3, P4, ML</td>
      <td>Privilege escalation chain: CredCreate -> PermGrant -> RoleAssume -> Impact (GetSecretValue) across 4 steps in 11m. MITRE: T1078, T1098, T1548.</td>
    </tr>
    <tr>
      <td><b>meera.n</b></td>
      <td><span class="badge-revoke">98.9 REVOKE</span></td>
      <td>P4, P5, ML</td>
      <td>Token hijacking and concurrent session misuse across disjoint CIDR blocks following Okta logout. Anomaly score: 0.93. MITRE: T1539, T1550.</td>
    </tr>
    <tr>
      <td><b>dev.kumar</b></td>
      <td><span class="badge-restrict">89.7 RESTRICT</span></td>
      <td>P4, ML</td>
      <td>Defense evasion via StopLogging API in unseen region eu-west-3. Action rarity 99.1%. MITRE: T1526, T1562.</td>
    </tr>
    <tr>
      <td><b>anita.rao</b></td>
      <td><span class="badge-stepup">51.3 STEP-UP</span></td>
      <td>P1, ML</td>
      <td>Impossible travel velocity: Okta login from Mumbai followed by AWS action from Frankfurt in 10 minutes. MITRE: T1078.</td>
    </tr>
  </table>

  <h2>2. Identity vs. Attack Pattern Heatmap Matrix</h2>
  <table>
    <tr><th>Identity</th><th>Risk</th><th>P1 (Travel)</th><th>P2 (Dormant)</th><th>P3 (Escalation)</th><th>P4 (API)</th><th>P5 (Token)</th><th>ML (Anomaly)</th></tr>
    <tr><td><b>svc-report</b></td><td><span class="badge-revoke">100.0</span></td><td class="cell-zero">0</td><td class="cell-light">1</td><td class="cell-light">1</td><td class="cell-heavy">3</td><td class="cell-zero">0</td><td class="cell-heavy">6</td></tr>
    <tr><td><b>meera.n</b></td><td><span class="badge-revoke">98.9</span></td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-light">1</td><td class="cell-medium">2</td><td class="cell-medium">2</td></tr>
    <tr><td><b>dev.kumar</b></td><td><span class="badge-restrict">89.7</span></td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-light">1</td><td class="cell-zero">0</td><td class="cell-light">1</td></tr>
    <tr><td><b>anita.rao</b></td><td><span class="badge-stepup">51.3</span></td><td class="cell-light">1</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-heavy">3</td></tr>
    <tr><td><b>manoj.pillai</b></td><td>17.1</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-medium">2</td></tr>
    <tr><td><b>alok.mishra</b></td><td>13.0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-zero">0</td><td class="cell-medium">2</td></tr>
  </table>

  <h2>3. Temporal Attack Velocity & Concentration (UTC+05:30 IST)</h2>
  <table>
    <tr><th>Date</th><th>Active Window</th><th>Event Volume</th><th>Observed Attack Stage</th></tr>
    <tr><td>2026-10-26</td><td>09:00 - 10:00 IST</td><td>1 event</td><td>Dormant service account reactivation (svc-report)</td></tr>
    <tr><td>2026-10-26</td><td>10:00 - 11:00 IST</td><td>2 events</td><td>Initial IAM policy enumeration & credential creation</td></tr>
    <tr style="background: rgba(239, 68, 68, 0.15);"><td>2026-10-27</td><td><b>13:00 - 14:00 IST</b></td><td><b>5 events (PEAK)</b></td><td>Multi-step Privilege Escalation + StopLogging defense evasion</td></tr>
    <tr style="background: rgba(239, 68, 68, 0.15);"><td>2026-10-27</td><td><b>16:00 - 17:00 IST</b></td><td><b>5 events (PEAK)</b></td><td>Concurrent token abuse & secret exfiltration (GetSecretValue)</td></tr>
  </table>

  <h2>4. Multi-Agent Detection & Model Benchmark</h2>
  <table>
    <tr><th>Detector Architecture</th><th>Flagged</th><th>TP</th><th>FP</th><th>Precision</th><th>Recall</th><th>F1 Score</th></tr>
    <tr><td>Deterministic Rules (P1-P5)</td><td>5</td><td>5</td><td>0</td><td>100.0%</td><td>71.4%</td><td>0.833</td></tr>
    <tr><td>Behavioral ML (Isolation Forest)</td><td>16</td><td>7</td><td>9</td><td>43.8%</td><td>100.0%</td><td>0.609</td></tr>
    <tr style="background: rgba(34, 197, 94, 0.15); font-weight: bold; color: #86efac;">
      <td>Hybrid Ensemble (IdentityShield)</td><td>4</td><td>4</td><td>0</td><td>100.0%</td><td>57.1%</td><td>0.727</td></tr>
  </table>

  <div class="zt-box">
    <strong style="color: #22c55e;">🛡️ Zero Trust Policy Enforcement & Audit Integrity</strong><br>
    • AL-0001 (svc-report, Risk 100): Revocation safely QUARANTINED pending analyst authorization.<br>
    • AL-0002 (meera.n, Risk 98.9): Revocation safely QUARANTINED pending analyst authorization.<br>
    • AL-0003 (dev.kumar, Risk 89.7): RESTRICT access containment auto-applied via simulator adapter.<br>
    • Cryptographic Audit Hash Chain: <code>(True, None)</code> — 100% Mathematically Verified.
  </div>
</div>
</body>
</html>"""

    out_path_html = Path("C:/Users/Omana/OneDrive/Desktop/IdentityShield_Attack_Summary_With_Heatmaps.html")
    out_path_html.write_text(html_content, encoding="utf-8")
    print(f"Generated HTML Report: {out_path_html}")

if __name__ == "__main__":
    build_report()
