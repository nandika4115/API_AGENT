import json
import os
from datetime import datetime
from agent.history import load_history

def export_json(result, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/scan_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)
    return filename

def export_pdf(result, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/scan_{timestamp}.pdf"

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import cm

    doc = SimpleDocTemplate(filename, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle("title", fontSize=20, fontName="Helvetica-Bold",
                                 textColor=colors.HexColor("#1a1a2e"), spaceAfter=8)
    sub_style = ParagraphStyle("sub", fontSize=10, fontName="Helvetica",
                               textColor=colors.grey, spaceAfter=20)

    elements.append(Paragraph("API Security Scan Report", title_style))
    elements.append(Paragraph(
        f"Target: {result.get('target', 'N/A')} &nbsp;|&nbsp; "
        f"Generated: {result.get('last_scan', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}",
        sub_style
    ))

    # Summary counts
    findings = result.get("findings", [])
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "PASS"]}

    summary_data = [
        ["Total Checks", "Critical", "High", "Medium", "Passed"],
        [str(len(findings)), str(counts["CRITICAL"]), str(counts["HIGH"]),
         str(counts["MEDIUM"]), str(counts["PASS"])]
    ]

    summary_table = Table(summary_data, colWidths=[3.2*cm]*5)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1d27")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("BACKGROUND", (0,1), (0,1), colors.HexColor("#1e2130")),
        ("BACKGROUND", (1,1), (1,1), colors.HexColor("#3a1a1a")),
        ("TEXTCOLOR",  (1,1), (1,1), colors.HexColor("#ff4d4d")),
        ("BACKGROUND", (2,1), (2,1), colors.HexColor("#2e1e00")),
        ("TEXTCOLOR",  (2,1), (2,1), colors.HexColor("#ff8c00")),
        ("BACKGROUND", (3,1), (3,1), colors.HexColor("#2e2800")),
        ("TEXTCOLOR",  (3,1), (3,1), colors.HexColor("#ffd700")),
        ("BACKGROUND", (4,1), (4,1), colors.HexColor("#0f2a15")),
        ("TEXTCOLOR",  (4,1), (4,1), colors.HexColor("#4caf50")),
        ("FONTNAME",   (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,1), (-1,1), 13),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [None]),
        ("BOX",        (0,0), (-1,-1), 0.5, colors.HexColor("#2a2d3e")),
        ("INNERGRID",  (0,0), (-1,-1), 0.5, colors.HexColor("#2a2d3e")),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.5*cm))

    # Findings table — only non-PASS
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "PASS": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f["severity"], 9))

    section_style = ParagraphStyle("section", fontSize=12, fontName="Helvetica-Bold",
                                   textColor=colors.HexColor("#1a1a2e"), spaceBefore=16, spaceAfter=8)
    elements.append(Paragraph("Findings", section_style))

    table_data = [["Check", "Endpoint", "Method", "Severity", "Detail"]]
    severity_colors = {
        "CRITICAL": colors.HexColor("#ff4d4d"),
        "HIGH":     colors.HexColor("#ff8c00"),
        "MEDIUM":   colors.HexColor("#ffd700"),
        "PASS":     colors.HexColor("#4caf50"),
    }

    cell_style = ParagraphStyle("cell", fontSize=7, fontName="Helvetica", leading=10)

    for f in sorted_findings:
        table_data.append([
            Paragraph(f["check"], cell_style),
            Paragraph(f["endpoint"], cell_style),
            f["method"],
            Paragraph(f"<b>{f['severity']}</b>", ParagraphStyle(
                "sev", fontSize=7, fontName="Helvetica-Bold",
                textColor=severity_colors.get(f["severity"], colors.black)
            )),
            Paragraph(f["detail"], cell_style),
        ])

    findings_table = Table(table_data, colWidths=[3.5*cm, 4.5*cm, 1.5*cm, 2*cm, 5.5*cm])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#1a1d27")),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 8),
        ("ALIGN",         (0,0), (-1,-1), "LEFT"),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#2a2d3e")),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, colors.HexColor("#dee2e6")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    elements.append(findings_table)

    doc.build(elements)
    return filename