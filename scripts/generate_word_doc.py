import os
from pathlib import Path
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

def add_code_block(doc, text):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, "F1F5F9")
    set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run(text)
    run.font.name = "Consolas"
    run.font.size = Pt(9.5)
    run.font.color.rgb = RGBColor(15, 23, 42)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def add_callout(doc, title, text, bg_hex="EFF6FF", border_hex="3B82F6"):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=160, bottom=160, left=200, right=200)
    
    # Left border styling
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
    run_title = p.add_run(f"🎤 {title}\n")
    run_title.bold = True
    run_title.font.name = "Segoe UI"
    run_title.font.size = Pt(10.5)
    run_title.font.color.rgb = RGBColor(30, 58, 138)
    
    run_text = p.add_run(f'"{text}"')
    run_text.italic = True
    run_text.font.name = "Segoe UI"
    run_text.font.size = Pt(10)
    run_text.font.color.rgb = RGBColor(30, 41, 59)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

def build_document(output_path):
    doc = Document()
    
    # Page Margins: 0.75 in
    for section in doc.sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)
        
    # Styles
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Segoe UI'
    normal_style.font.size = Pt(10)
    normal_style.font.color.rgb = RGBColor(51, 65, 85)
    
    # Header / Title Block
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(2)
    run_title = title_p.add_run("IdentityShield: Presentation Test Cases")
    run_title.bold = True
    run_title.font.size = Pt(22)
    run_title.font.color.rgb = RGBColor(15, 23, 42)
    
    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_before = Pt(0)
    sub_p.paragraph_format.space_after = Pt(12)
    run_sub = sub_p.add_run("Track 2: Zero Trust for Everyone | 5 High-Impact Demo Scenarios & Judge Pitch Notes")
    run_sub.font.size = Pt(12)
    run_sub.font.color.rgb = RGBColor(37, 99, 235)
    run_sub.bold = True
    
    # Metadata Box
    meta_table = doc.add_table(rows=2, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_table.autofit = False
    for r in range(2):
        for c in range(2):
            cell = meta_table.cell(r, c)
            cell.width = Inches(3.25)
            set_cell_background(cell, "F8FAFC")
            set_cell_margins(cell, top=80, bottom=80, left=120, right=120)
            
    meta_table.cell(0, 0).paragraphs[0].add_run("Project: IdentityShield Multi-Agent Platform").bold = True
    meta_table.cell(0, 1).paragraphs[0].add_run("Recipient: forclaudelesgo@gmail.com").bold = True
    meta_table.cell(1, 0).paragraphs[0].add_run("Working Directory: IdentityShield_BuildKit_v2/identityshield").font.size = Pt(9)
    meta_table.cell(1, 1).paragraphs[0].add_run("Dashboard URL: http://127.0.0.1:8000").font.size = Pt(9)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(10)
    
    # Instructions Section
    h2 = doc.add_heading(level=2)
    h2.paragraph_format.space_before = Pt(8)
    h2.paragraph_format.space_after = Pt(4)
    run_h2 = h2.add_run("How to Run These in PowerShell")
    run_h2.font.color.rgb = RGBColor(15, 23, 42)
    run_h2.font.size = Pt(14)
    
    intro_p = doc.add_paragraph()
    intro_p.paragraph_format.space_after = Pt(4)
    intro_p.add_run("Open PowerShell, ensure you are in the project folder, and copy-paste any command below:")
    add_code_block(doc, "cd C:\\Users\\Omana\\Downloads\\IdentityShield_BuildKit_v2\\identityshield")
    
    # 5 TEST CASES
    test_cases = [
        {
            "num": "1",
            "name": "Impossible Travel Attack (Cross-Cloud Identity Correlation)",
            "file": "tests/test_detectors.py",
            "tag": "test_p1_impossible_travel",
            "cmd": ".\\.venv\\Scripts\\python.exe -m pytest tests/test_detectors.py -k \"test_p1_impossible_travel\" -v",
            "what": "Evaluates the ImpossibleTravelAgent correlating Okta IdP logins with AWS CloudTrail API events. Detects user 'anita.rao' executing actions from physically impossible geographical locations within 10 minutes, generating a severity 1.0 alert mapped to MITRE ATT&CK T1078 (Valid Accounts).",
            "output": "tests/test_detectors.py::test_p1_impossible_travel PASSED    [100%]\n1 passed, 5 deselected in 0.45s",
            "pitch": "Legacy SIEMs inspect AWS and Okta in isolated silos. IdentityShield correlates identity sessions across both providers in real time, detecting physically impossible travel velocity anomalies and binding evidence directly to MITRE ATT&CK T1078."
        },
        {
            "num": "2",
            "name": "Stealth Privilege Escalation Chain (Causal Graph Reconstruction)",
            "file": "tests/test_detectors.py",
            "tag": "test_p3_privilege_escalation",
            "cmd": ".\\.venv\\Scripts\\python.exe -m pytest tests/test_detectors.py -k \"test_p3_privilege_escalation\" -v",
            "what": "Tests PrivEscalationAgent on multi-step IAM modifications. Verifies that dormant service account 'svc-report' suddenly chaining CreatePolicyVersion and AttachUserPolicy is recognized as a coordinated attack sequence with an unbroken causal graph.",
            "output": "tests/test_detectors.py::test_p3_privilege_escalation PASSED [100%]\n1 passed, 5 deselected in 0.40s",
            "pitch": "Sophisticated adversaries avoid single obvious alarms; they chain small, benign-looking IAM actions. Our graph-based privilege escalation detector reconstructs causal event dependencies across AWS CloudTrail to catch stealth grants before data exfiltration occurs."
        },
        {
            "num": "3",
            "name": "Zero Trust Containment & Analyst Approval Gate (Human-in-the-Loop)",
            "file": "tests/test_scoring.py",
            "tag": "test_revoke_without_approval_refused",
            "cmd": ".\\.venv\\Scripts\\python.exe -m pytest tests/test_scoring.py -k \"test_revoke_without_approval_refused\" -v",
            "what": "Demonstrates strict Zero Trust containment policy: high-risk remediation actions ('revoke') are strictly REFUSED unless signed off by an authorized analyst ('analyst_jane'). Prevents automated SOAR lockouts and denial-of-service on legitimate pipelines.",
            "output": "tests/test_scoring.py::test_revoke_without_approval_refused PASSED [100%]\n1 passed, 4 deselected in 0.12s",
            "pitch": "Zero Trust demands safety and governance. Our automated response engine mathematically refuses destructive revocation actions unless signed off by an authorized security analyst, preventing automated remediation from causing accidental operational downtime."
        },
        {
            "num": "4",
            "name": "Tamper-Evident SHA-256 Cryptographic Audit Ledger",
            "file": "tests/test_v21_trace.py",
            "tag": "test_each_threat_gets_its_own_audit_entry_and_dedupes",
            "cmd": ".\\.venv\\Scripts\\python.exe -m pytest tests/test_v21_trace.py -k \"test_each_threat_gets_its_own_audit_entry_and_dedupes\" -v",
            "what": "Validates that every single threat detection produces an immutable SHA-256 hash-chained audit record in SQLite. Deduplicates repeat scans to eliminate alert fatigue and runs audit.verify() returning (True, None) indicating cryptographic ledger integrity.",
            "output": "tests/test_v21_trace.py::test_each_threat_gets_its_own_audit_entry_and_dedupes PASSED [100%]\n1 passed, 8 deselected in 0.18s",
            "pitch": "Every detection and containment decision is sealed into a tamper-evident SHA-256 hash-chained ledger. If an intruder attempts to delete or alter historical incident records, the cryptographic signature immediately breaks, providing compliance auditors mathematical proof of integrity."
        },
        {
            "num": "5",
            "name": "Adaptive Learning Feedback Loop (Dynamic Bayesian Weight Tuning)",
            "file": "tests/test_scoring.py",
            "tag": "test_feedback_tp_raises_weight",
            "cmd": ".\\.venv\\Scripts\\python.exe -m pytest tests/test_scoring.py -k \"test_feedback_tp_raises_weight\" -v",
            "what": "Tests active feedback learning: when an analyst marks an incident as a True Positive (TP), the scoring engine dynamically updates detector weights in SQLite, tuning the multi-agent ensemble to the organization's specific threat patterns.",
            "output": "tests/test_scoring.py::test_feedback_tp_raises_weight PASSED [100%]\n1 passed, 4 deselected in 0.12s",
            "pitch": "IdentityShield gets smarter with every triage. When a security analyst verifies a detection as a True Positive, our Bayesian feedback loop immediately boosts the detector's weight in real time without requiring code deployments or pipeline restarts."
        }
    ]
    
    for tc in test_cases:
        h3 = doc.add_heading(level=3)
        h3.paragraph_format.space_before = Pt(14)
        h3.paragraph_format.space_after = Pt(2)
        r_h3 = h3.add_run(f"Test Case {tc['num']}: {tc['name']}")
        r_h3.font.color.rgb = RGBColor(30, 41, 59)
        r_h3.font.size = Pt(12)
        
        # Details bullet
        p_desc = doc.add_paragraph()
        p_desc.paragraph_format.space_after = Pt(4)
        p_desc.add_run("What It Verifies: ").bold = True
        p_desc.add_run(tc['what'])
        
        p_cmd_label = doc.add_paragraph()
        p_cmd_label.paragraph_format.space_before = Pt(2)
        p_cmd_label.paragraph_format.space_after = Pt(2)
        p_cmd_label.add_run("Terminal Command:").bold = True
        add_code_block(doc, tc['cmd'])
        
        p_out_label = doc.add_paragraph()
        p_out_label.paragraph_format.space_before = Pt(2)
        p_out_label.paragraph_format.space_after = Pt(2)
        p_out_label.add_run("Expected Terminal Output:").bold = True
        add_code_block(doc, tc['output'])
        
        add_callout(doc, "30-Second Presentation Pitch for Judges", tc['pitch'])
        
    # GRAND FINALE SECTION
    doc.add_page_break()
    h2_finale = doc.add_heading(level=2)
    h2_finale.paragraph_format.space_before = Pt(12)
    h2_finale.paragraph_format.space_after = Pt(4)
    r_fin = h2_finale.add_run("Grand Finale: Live 15-Agent CLI Terminal Scan")
    r_fin.font.color.rgb = RGBColor(15, 23, 42)
    r_fin.font.size = Pt(14)
    
    p_fin = doc.add_paragraph()
    p_fin.paragraph_format.space_after = Pt(4)
    p_fin.add_run("To demonstrate the full system in action during Q&A or live demo, run the streaming terminal scanner:")
    add_code_block(doc, ".\\.venv\\Scripts\\python.exe -m app.scan --sample --delay 0.02")
    
    p_fin_desc = doc.add_paragraph()
    p_fin_desc.paragraph_format.space_after = Pt(4)
    p_fin_desc.add_run("What judges will see live in your console:").bold = True
    
    bullets = [
        "15 Specialized Agents executing across 5 architectural layers (Ingestion, Normalization, Correlation, Detection, Scoring & Containment).",
        "Colorized ANSI threat banners for detected incidents (Anita Rao P1, Dormant svc-report P2/P3, Token Abuse P5).",
        "Instant risk scoring, containment tier recommendation (step_up, restrict, revoke), and SHA-256 cryptographic audit ledger verification.",
        "Zero-delay UI sync: the web dashboard at http://127.0.0.1:8000 updates simultaneously with attack graph explorer and telemetry."
    ]
    for b in bullets:
        bp = doc.add_paragraph(style='List Bullet')
        bp.paragraph_format.space_before = Pt(0)
        bp.paragraph_format.space_after = Pt(2)
        bp.add_run(b)
        
    doc.add_paragraph().paragraph_format.space_after = Pt(6)
    add_callout(
        doc, 
        "Grand Finale Pitch", 
        "IdentityShield isn't a mock UI or a slide deck. Our 15 agents run in production, parse raw cloud logs, correlate identities across AWS and Okta, score risks mathematically, and maintain a tamper-evident audit ledger that is 100% automated and verifiable.",
        bg_hex="F0FDF4",
        border_hex="22C55E"
    )
    
    # Save document
    doc.save(str(output_path))
    print(f"Successfully generated document at: {output_path}")

if __name__ == "__main__":
    dest1 = Path("C:/Users/Omana/OneDrive/Desktop/IdentityShield_Presentation_Test_Cases.docx")
    build_document(dest1)
    
    alt_dest = Path("C:/Users/Omana/Desktop/IdentityShield_Presentation_Test_Cases.docx")
    try:
        build_document(alt_dest)
    except Exception:
        pass
