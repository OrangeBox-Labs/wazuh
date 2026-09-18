#!/usr/bin/env python3
"""OrangeBox Wazuh Security Dashboard PDF.

Genera un dashboard PDF visual, independiente del HTML de correo.
La extracción de datos se delega íntegramente a orangebox-security-report.py.
Requiere reportlab.
"""

import argparse
import os
import re
import smtplib
import urllib.request
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        HRFlowable,
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.graphics.charts.legends import Legend
    from reportlab.graphics.charts.piecharts import Pie
except ImportError as exc:
    raise SystemExit(
        "Falta reportlab. Instálalo en el entorno que ejecutará este reporte "
        "(por ejemplo, el paquete python3-reportlab)."
    ) from exc


BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "orangebox-security-report.py"
DEFAULT_FROM = "wazuh@orangebox.cl"
SMTP_HOST = "localhost"
SMTP_PORT = 25
LOGO_URL = "https://www.orangebox.cl/obox/img/logo-dark.png"

NAVY = colors.HexColor("#182a33")
NAVY2 = colors.HexColor("#213b46")
ORANGE = colors.HexColor("#f58220")
ORANGE_DARK = colors.HexColor("#d65d00")
TEXT = colors.HexColor("#263238")
MUTED = colors.HexColor("#607d8b")
BORDER = colors.HexColor("#d7e0e4")
TRACK = colors.HexColor("#e7edef")
LIGHT = colors.HexColor("#f3f6f7")
WHITE = colors.white
RED = colors.HexColor("#c43d2b")
RED_DARK = colors.HexColor("#6b2923")
GREEN = colors.HexColor("#147a4a")


def load_report_module():
    spec = spec_from_file_location("orangebox_security_report", REPORT_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"No se pudo cargar {REPORT_PATH}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def num(value):
    return f"{int(value):,}".replace(",", ".")


def esc(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def logo_path():
    target = Path("/tmp/orangebox-dashboard-logo.png")
    try:
        if not target.exists():
            urllib.request.urlretrieve(LOGO_URL, target)
        return target
    except Exception:
        return None


class DashboardDocTemplate(BaseDocTemplate):
    def __init__(self, filename, **kwargs):
        super().__init__(filename, pagesize=landscape(A4), **kwargs)
        width, height = landscape(A4)
        frame = Frame(12 * mm, 12 * mm, width - 24 * mm, height - 24 * mm,
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([])


def make_styles():
    styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "DashTitle", parent=styles["Title"], fontName="Helvetica-Bold",
            fontSize=22, leading=24, textColor=WHITE, spaceAfter=2
        ),
        "subtitle": ParagraphStyle(
            "DashSubtitle", parent=styles["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=colors.HexColor("#cbd7dc")
        ),
        "section": ParagraphStyle(
            "Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
            fontSize=12, leading=14, textColor=TEXT, spaceAfter=5
        ),
        "small": ParagraphStyle(
            "Small", parent=styles["Normal"], fontName="Helvetica",
            fontSize=7.5, leading=9.5, textColor=MUTED
        ),
        "body": ParagraphStyle(
            "Body", parent=styles["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=TEXT
        ),
        "tiny": ParagraphStyle(
            "Tiny", parent=styles["Normal"], fontName="Helvetica",
            fontSize=6.5, leading=8, textColor=MUTED
        ),
        "kpi": ParagraphStyle(
            "Kpi", parent=styles["Normal"], fontName="Helvetica-Bold",
            fontSize=20, leading=21, alignment=TA_LEFT, textColor=ORANGE
        ),
        "kpilabel": ParagraphStyle(
            "KpiLabel", parent=styles["Normal"], fontName="Helvetica-Bold",
            fontSize=7.5, leading=9, textColor=WHITE
        ),
        "kpinote": ParagraphStyle(
            "KpiNote", parent=styles["Normal"], fontName="Helvetica",
            fontSize=6.5, leading=8, textColor=colors.HexColor("#c8d7dc")
        ),
        "right": ParagraphStyle(
            "Right", parent=styles["Normal"], fontName="Helvetica",
            fontSize=7.5, leading=9, textColor=MUTED, alignment=TA_RIGHT
        ),
    }


def header_table(group, label, period, styles):
    logo = logo_path()
    if logo:
        logo_flow = Image(str(logo), width=45 * mm, height=13 * mm, kind="proportional")
    else:
        logo_flow = Paragraph(
            "<font color='#f58220'><b>Orange</b></font><font color='#ffffff'><b>Box</b></font>",
            ParagraphStyle("LogoFallback", fontName="Helvetica-Bold", fontSize=20)
        )

    right = [
        Paragraph("SECURITY DASHBOARD", styles["title"]),
        Paragraph(f"WAZUH · {esc(label.upper())} · {esc(group)}", styles["subtitle"]),
    ]
    t = Table([[logo_flow, right]], colWidths=[100 * mm, 167 * mm], rowHeights=[20 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 3, ORANGE),
    ]))
    context = Table(
        [[Paragraph("<b>Resumen de seguridad</b>", ParagraphStyle(
            "Context", fontName="Helvetica-Bold", fontSize=15, textColor=TEXT
        )),
          Paragraph(f"<b>Período:</b> {esc(period)}<br/><b>Grupo:</b> {esc(group)}",
                    styles["right"])]],
        colWidths=[150 * mm, 117 * mm],
    )
    context.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [t, Spacer(1, 4 * mm), context, Spacer(1, 5 * mm)]


def kpi_card(label, value, note, accent=ORANGE, width=65 * mm, styles=None):
    inner = [
        Paragraph(num(value), ParagraphStyle(
            "KpiValue", fontName="Helvetica-Bold", fontSize=22, leading=22, textColor=accent
        )),
        Paragraph(label.upper(), styles["kpilabel"]),
        Spacer(1, 1 * mm),
        Paragraph(note, styles["kpinote"]),
    ]
    t = Table([[inner]], colWidths=[width], rowHeights=[24 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY2),
        ("LINEBELOW", (0, 0), (-1, -1), 3, accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def category_chart(categories):
    labels = []
    values = []
    icons = {
        "authentication": "Autenticación",
        "web": "Web",
        "fim": "Integridad de archivos",
        "malware": "Malware / WebShell",
        "privilege": "Privilegios",
        "attack": "Ataques",
    }
    for key, label in icons.items():
        value = categories.get(key, {}).get("count", 0)
        if value:
            labels.append(label)
            values.append(value)

    drawing = Drawing(267 * mm, 72 * mm)
    if not values:
        drawing.add(String(5, 30, "Sin datos para el período", fillColor=MUTED, fontSize=10))
        return drawing

    chart = HorizontalBarChart()
    chart.x = 82
    chart.y = 8
    chart.width = 170 * mm
    chart.height = 58 * mm
    chart.data = [values]
    chart.categoryAxis.categoryNames = labels
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values) * 1.08
    chart.valueAxis.valueStep = max(1, int(max(values) / 4))
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.labels.fontSize = 6
    chart.bars[0].fillColor = ORANGE
    chart.bars[0].strokeColor = ORANGE
    chart.valueAxis.strokeColor = BORDER
    chart.valueAxis.gridStrokeColor = TRACK
    chart.categoryAxis.strokeColor = BORDER
    drawing.add(chart)
    return drawing


def timeline_chart(timeline):
    drawing = Drawing(267 * mm, 55 * mm)
    if not timeline:
        drawing.add(String(5, 25, "Sin evolución temporal disponible", fillColor=MUTED, fontSize=9))
        return drawing

    dates = sorted(timeline)
    values = [timeline[d] for d in dates]
    chart = HorizontalLineChart()
    chart.x = 48
    chart.y = 8
    chart.width = 225 * mm
    chart.height = 40 * mm
    chart.data = [values]
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values) * 1.1 or 1
    chart.valueAxis.labels.fontSize = 6
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.strokeColor = BORDER
    chart.valueAxis.gridStrokeColor = TRACK
    chart.lines[0].strokeColor = ORANGE
    chart.lines[0].strokeWidth = 2
    chart.lines[0].symbol = None
    chart.categoryAxis.categoryNames = [d.strftime("%d/%m") for d in dates]
    chart.categoryAxis.labels.fontSize = 6
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.strokeColor = BORDER
    drawing.add(chart)
    return drawing


def ranking_table(title, rows, accent=ORANGE):
    data = [[
        Paragraph(f"<b>{esc(title)}</b>", ParagraphStyle("RHead", fontName="Helvetica-Bold", fontSize=9, textColor=WHITE)),
        Paragraph("<b>Volumen</b>", ParagraphStyle("RHead2", fontName="Helvetica-Bold", fontSize=8, textColor=WHITE)),
    ]]
    max_value = max((int(v) for _label, v in rows), default=1)
    for index, (label, value) in enumerate(rows, 1):
        label = str(label)
        if len(label) > 48:
            label = label[:45] + "..."
        bar_width = max(4, int((float(value) / max_value) * 58))
        bar = Table([[""]], colWidths=[bar_width * mm], rowHeights=[2.8 * mm])
        bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), accent)]))
        data.append([
            [
                Paragraph(f"<b>{index}. {esc(label)}</b>", ParagraphStyle(
                    f"R{index}", fontName="Helvetica", fontSize=7.2, textColor=TEXT
                )),
                bar,
            ],
            Paragraph(num(value), ParagraphStyle(
                f"RV{index}", fontName="Helvetica-Bold", fontSize=7.2, textColor=TEXT, alignment=TA_RIGHT
            )),
        ])

    t = Table(data, colWidths=[55 * mm, 15 * mm])
    t.setStyle(TableStyle([
        ("SPAN", (0, 0), (-1, 0)),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY2),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, BORDER),
    ]))
    return t


def detail_table(title, rows, headers):
    data = [[Paragraph(f"<b>{esc(h)}</b>", ParagraphStyle(
        f"H{idx}", fontName="Helvetica-Bold", fontSize=7, textColor=WHITE
    )) for idx, h in enumerate(headers)]]
    for row in rows:
        data.append([Paragraph(esc(value), ParagraphStyle(
            "D", fontName="Helvetica", fontSize=6.5, leading=8, textColor=TEXT
        )) for value in row])

    t = Table(data, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY2),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return [Paragraph(title, ParagraphStyle(
        "DT", fontName="Helvetica-Bold", fontSize=10, textColor=TEXT, spaceAfter=2
    )), t]


def build_pdf(path, summary, group, start, end, label, report):
    styles = make_styles()
    period = (
        f"{start.strftime('%d/%m/%Y %H:%M')} — "
        f"{end.strftime('%d/%m/%Y %H:%M') if end <= datetime.now().astimezone() else 'ahora'}"
    )

    doc = BaseDocTemplate(
        str(path),
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=f"OrangeBox Security Dashboard - {group}",
        author="OrangeBox IT Services",
    )
    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height,
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        id="dashboard",
    )
    doc.addPageTemplates([])

    from reportlab.platypus import PageTemplate
    doc.addPageTemplates([PageTemplate(id="dashboard", frames=[frame])])

    story = []
    story.extend(header_table(group, label, period, styles))

    # KPI row.
    blocked_ips = len(summary["firewall_ips"])
    kpis = Table([[
        kpi_card("Eventos", summary["security_count"], "detecciones clasificadas", ORANGE, styles=styles),
        kpi_card("Alta severidad", summary["critical_count"], "nivel Wazuh ≥ 13", RED, styles=styles),
        kpi_card("IPs atacantes", len(summary["source_ips"]), "orígenes observados", ORANGE, styles=styles),
        kpi_card("IPs bloqueadas", blocked_ips, "firewall-drop / Active Response", RED, styles=styles),
    ]], colWidths=[68 * mm] * 4)
    kpis.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.extend([kpis, Spacer(1, 5 * mm)])

    # Main visual area.
    category_box = Table([[
        [Paragraph("Actividad por categoría", styles["section"]),
         category_chart(summary["categories"])]
    ]], colWidths=[174 * mm])
    category_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("LINEABOVE", (0, 0), (-1, 0), 3, ORANGE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    firewall_attempts = sum(row["attempts"] for row in summary["firewall_rows"])
    blocked_text = [
        Paragraph(num(blocked_ips), ParagraphStyle(
            "Blocked", fontName="Helvetica-Bold", fontSize=32, textColor=RED, alignment=TA_LEFT
        )),
        Paragraph("IPs ATACANTES BLOQUEADAS", ParagraphStyle(
            "BlockedLabel", fontName="Helvetica-Bold", fontSize=7, textColor=TEXT
        )),
        Spacer(1, 2 * mm),
        Paragraph(
            f"{num(firewall_attempts)} intentos asociados<br/>Active Response · firewall-drop",
            styles["small"],
        ),
    ]
    blocked_box = Table([[blocked_text]], colWidths=[88 * mm], rowHeights=[73 * mm])
    blocked_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff6f4")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#efd8d4")),
        ("LINEABOVE", (0, 0), (-1, 0), 3, RED),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    main_row = Table([[category_box, blocked_box]], colWidths=[176 * mm, 91 * mm])
    main_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.extend([main_row, Spacer(1, 4 * mm)])

    # Temporal evolution.
    story.append(Table([[
        [Paragraph("Evolución de eventos", styles["section"]),
         timeline_chart(summary.get("timeline", {}))]
    ]], colWidths=[267 * mm], style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("LINEABOVE", (0, 0), (-1, 0), 3, ORANGE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])))

    story.append(PageBreak())

    # Page 2: compact rankings and operational details.
    story.extend([
        Paragraph("Actividad destacada", ParagraphStyle(
            "P2", fontName="Helvetica-Bold", fontSize=18, textColor=TEXT
        )),
        Paragraph(
            "Top de sistemas, reglas y técnicas MITRE del mismo período y grupo.",
            styles["small"],
        ),
        Spacer(1, 4 * mm),
    ])

    categories = summary["categories"]
    rule_counter = {}
    from collections import Counter
    rc = Counter()
    for info in categories.values():
        rc.update(info.get("rules") or {})
    rules = []
    for key, count in rc.most_common(5):
        if isinstance(key, tuple):
            rules.append((f"{key[0]} · {key[1]}", count))
        else:
            rules.append((str(key), count))

    systems = []
    for key, count in summary["agents"].most_common(5):
        systems.append((key[1] if isinstance(key, tuple) else str(key), count))

    mitre = [
        (f"{mid} · {name}", count)
        for mid, name, _meaning, count in report.mitre_rows(summary)[:5]
    ]

    rankings = Table([[
        ranking_table("Top 5 sistemas", systems, ORANGE),
        ranking_table("Top 5 reglas", rules, ORANGE_DARK),
        ranking_table("Top 5 MITRE ATT&CK", mitre, RED),
    ]], colWidths=[91 * mm] * 3)
    rankings.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.extend([rankings, Spacer(1, 5 * mm)])

    # Firewall detail: actual 651 executions, not just trigger rules.
    # First show one row per origin rule with the total impact.
    fw_rows = []
    for row in summary["firewall_rows"]:
        fw_rows.append([
            row["agent_name"],
            row["rule_id"],
            row["description"],
            num(row["attempts"]),
            num(len(row["ips"])),
        ])
    if fw_rows:
        story.extend(detail_table(
            "Bloqueos automáticos registrados por Wazuh",
            fw_rows,
            ["Sistema", "Regla origen", "Motivo", "Intentos", "IPs bloqueadas"],
        ))

        # Then show EVERY blocked IP. This is intentionally separate
        # from the grouped rule summary so the dashboard does not
        # truncate the list to the first N addresses.
        ip_rows = []
        for row in summary["firewall_rows"]:
            for srcip in row["ips"]:
                ip_rows.append([
                    row["agent_name"],
                    row["rule_id"],
                    srcip,
                ])

        if ip_rows:
            story.extend([
                Spacer(1, 4 * mm),
                *detail_table(
                    "Detalle completo de IPs bloqueadas",
                    ip_rows,
                    ["Sistema", "Regla origen", "IP bloqueada"],
                ),
            ])
    else:
        story.append(Table(
            [[Paragraph(
                "No se encontraron ejecuciones firewall-drop registradas como regla 651 en el período.",
                styles["body"],
            )]],
            colWidths=[267 * mm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff6f4")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#efd8d4")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]),
        ))

    story.append(Spacer(1, 5 * mm))

    # Category detail, kept compact for operational use.
    cat_rows = []
    for key, info in sorted(categories.items(), key=lambda item: item[1]["count"], reverse=True):
        cat_rows.append([
            key.replace("_", " ").title(),
            num(info["count"]),
            num(len(info["ips"])),
            num(len(info["agents"])),
        ])
    story.extend(detail_table(
        "Resumen por categoría",
        cat_rows,
        ["Categoría", "Detecciones", "IPs", "Sistemas"],
    ))

    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "Fuente: Wazuh. El dashboard utiliza la misma extracción y clasificación del informe de actividad. "
        "Las IPs bloqueadas corresponden a ejecuciones de Active Response firewall-drop registradas por Wazuh, "
        "no simplemente a reglas configuradas para ejecutar un bloqueo.",
        styles["tiny"],
    ))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, 0, landscape(A4)[0], 7 * mm, fill=1, stroke=0)
        canvas.setFillColor(ORANGE)
        canvas.rect(0, 7 * mm, landscape(A4)[0], 1.5 * mm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(12 * mm, 2.5 * mm, "ORANGEBOX IT SERVICES · WAZUH SECURITY DASHBOARD")
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 2.5 * mm, f"Página {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def send_email(subject, pdf_path, recipients, sender=DEFAULT_FROM):
    for recipient in recipients:
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = f"Wazuh SOC <{sender}>"
        msg["To"] = recipient
        msg.attach(MIMEText("Adjunto: OrangeBox Wazuh Security Dashboard en PDF.", "plain", "utf-8"))
        with open(pdf_path, "rb") as handle:
            part = MIMEApplication(handle.read(), _subtype="pdf")
        part.add_header("Content-Disposition", "attachment", filename=os.path.basename(pdf_path))
        msg.attach(part)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.sendmail(sender, [recipient], msg.as_string())


def main():
    parser = argparse.ArgumentParser(description="OrangeBox Wazuh Security Dashboard PDF")
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ("today", "yesterday", "thisweek", "lastweek", "thismonth", "lastmonth", "thisyear", "lastyear"):
        modes.add_argument("--" + name, action="store_true")
    modes.add_argument("--date", metavar="YYYY-MM-DD")
    parser.add_argument("--group", required=True, help="Grupo Wazuh o all")
    parser.add_argument("--output", help="PDF de salida")
    parser.add_argument("--email", action="append", help="Destinatario; puede repetirse o usar comas")
    args = parser.parse_args()

    recipients = []
    for value in args.email or []:
        recipients.extend(item.strip() for item in value.split(",") if item.strip())
    for recipient in recipients:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+", recipient):
            raise SystemExit(f"Dirección de correo inválida: {recipient}")

    mode = args.date and f"date:{args.date}" or next(
        name for name in (
            "today", "yesterday", "thisweek", "lastweek",
            "thismonth", "lastmonth", "thisyear", "lastyear",
        ) if getattr(args, name)
    )

    report = load_report_module()
    now = datetime.now().astimezone()
    start, end, label = report.period_bounds(mode, now)
    allowed = report.group_members(args.group)
    summary = report.load_events(start, end, allowed)

    safe_group = "".join(c if c.isalnum() or c in "._-" else "_" for c in args.group)
    output = Path(args.output) if args.output else Path("/tmp") / f"security-dashboard-{safe_group}-{start:%Y%m%d}.pdf"
    output.parent.mkdir(parents=True, exist_ok=True)

    build_pdf(output, summary, args.group, start, end, label, report)

    if recipients:
        subject_prefix = {
            "today": "Dashboard Diario de Seguridad",
            "yesterday": "Dashboard Diario de Seguridad",
            "thisweek": "Dashboard Semanal de Seguridad",
            "lastweek": "Dashboard Semanal de Seguridad",
            "thismonth": "Dashboard Mensual de Seguridad",
            "lastmonth": "Dashboard Mensual de Seguridad",
            "thisyear": "Dashboard Anual de Seguridad",
            "lastyear": "Dashboard Anual de Seguridad",
        }
        subject = f"[ORANGEBOX] {subject_prefix.get(mode, 'Dashboard de Seguridad')} — {args.group}"
        send_email(subject, output, recipients)

    print(f"Dashboard PDF generado: {output}")
    print(f"IPs bloqueadas: {len(summary['firewall_ips'])}")
    print(f"Eventos de seguridad: {summary['security_count']}")
    if recipients:
        print(f"Enviado a: {', '.join(recipients)}")


if __name__ == "__main__":
    main()
