# ============================================================
# AegisRecon AI — Basic PDF Report Generation
# ============================================================

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
from pathlib import Path
import os

def generate_pdf_report(scan, findings, risk_score, recon_data, company_config):
    reports_dir = Path("instance/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    filename = f"report_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    filepath = reports_dir / filename

    doc = SimpleDocTemplate(str(filepath), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(f"<b>AegisRecon AI - Vulnerability Report</b>", styles['Title']))
    story.append(Paragraph(f"Target: {scan.target}", styles['Heading2']))
    story.append(Spacer(1, 12))

    # Risk Score
    if risk_score:
        story.append(Paragraph(f"Business Risk Score: {risk_score.overall_score:.1f}/100 - {risk_score.risk_level.upper()}", 
                             styles['Heading2']))
        story.append(Spacer(1, 12))

    # Findings Table
    if findings:
        data = [["Severity", "Title", "Module"]]
        for f in findings:
            data.append([f.severity.upper(), f.title, f.module])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)

    doc.build(story)
    
    return str(filepath), filename