"""
Intelligent Vulnerability Detection and Analysis Framework (IVDF)
Professional Report Generator — v2 Enhanced Edition

Design Philosophy:
  - Light paper-toned background (#F8F9FA) for print-friendliness
  - Deep slate typography (#1A202C) for maximum readability
  - Muted navy accent (#1E3A5F) for authoritative headers
  - Severity colours are desaturated and professional (not neon)
  - Ultra-thin hairline borders replace harsh grids
  - Generous whitespace creates premium breathing room
  - Cover block uses a full-width dark banner with white reverse text
  - Section headings anchored by a 3pt left accent rule
  - Vulnerability cards use a thin top-border colour strip + soft shadow-
    simulated background tiers
"""

import os
import json
import csv

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)
from reportlab.platypus.flowables import Flowable

# ══════════════════════════════════════════════════════
#  DESIGN TOKENS  —  edit here to retheme the entire PDF
# ══════════════════════════════════════════════════════

# Page / background
PAGE_BG         = colors.HexColor("#F8F9FA")   # warm off-white — print friendly
COVER_BG        = colors.HexColor("#1E3A5F")   # deep navy cover band
COVER_RULE      = colors.HexColor("#2D5F9A")   # lighter navy rule in cover

# Typography
INK_PRIMARY     = colors.HexColor("#1A202C")   # near-black — max readability
INK_SECONDARY   = colors.HexColor("#4A5568")   # slate — labels / captions
INK_TERTIARY    = colors.HexColor("#718096")   # grey — sub-labels / footers
INK_REVERSED    = colors.HexColor("#EDF2F7")   # off-white for dark backgrounds
INK_ACCENT      = colors.HexColor("#2B6CB0")   # mid-blue for hyperlinks / tags

# Structural chrome
ACCENT_NAVY     = colors.HexColor("#1E3A5F")   # section heading left-rule
HAIRLINE        = colors.HexColor("#CBD5E0")   # ultra-thin border / separator
DIVIDER         = colors.HexColor("#E2E8F0")   # row separator in tables

# Card / surface tiers
SURFACE_0       = colors.HexColor("#FFFFFF")   # card background
SURFACE_1       = colors.HexColor("#F0F4F8")   # alternating row tint
SURFACE_HEADER  = colors.HexColor("#2D3748")   # dark table header band

# ── Severity palette  (muted, professional) ───────────
SEV_INK = {
    "CRITICAL": colors.HexColor("#9B1C1C"),   # deep crimson text
    "HIGH":     colors.HexColor("#92400E"),   # burnt amber
    "MEDIUM":   colors.HexColor("#78350F"),   # dark gold / ochre
    "LOW":      colors.HexColor("#1E40AF"),   # deep blue
    "INFO":     colors.HexColor("#374151"),   # dark graphite
}
SEV_BG = {
    "CRITICAL": colors.HexColor("#FEE2E2"),   # blush
    "HIGH":     colors.HexColor("#FEF3C7"),   # cream amber
    "MEDIUM":   colors.HexColor("#FFFBEB"),   # pale gold
    "LOW":      colors.HexColor("#DBEAFE"),   # pale sky
    "INFO":     colors.HexColor("#F3F4F6"),   # light grey
}
SEV_BORDER = {
    "CRITICAL": colors.HexColor("#FECACA"),
    "HIGH":     colors.HexColor("#FDE68A"),
    "MEDIUM":   colors.HexColor("#FDE68A"),
    "LOW":      colors.HexColor("#BFDBFE"),
    "INFO":     colors.HexColor("#D1D5DB"),
}
SEV_RULE = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH":     colors.HexColor("#D97706"),
    "MEDIUM":   colors.HexColor("#B45309"),
    "LOW":      colors.HexColor("#2563EB"),
    "INFO":     colors.HexColor("#6B7280"),
}


# ══════════════════════════════════════════════════════
#  CUSTOM FLOWABLES
# ══════════════════════════════════════════════════════

class SectionRule(Flowable):
    """
    Premium section heading block:
      left 3pt navy accent bar  |  heading text  |  hairline rule to right edge
    Renders entirely on canvas so no font/paragraph quirks.
    """
    def __init__(self, text, font_size=11, top_space=18, bottom_space=10):
        super().__init__()
        self.text         = text
        self.font_size    = font_size
        self.top_space    = top_space
        self.bottom_space = bottom_space
        self._height      = top_space + font_size * 1.4 + bottom_space

    def wrap(self, availWidth, availHeight):
        self._w = availWidth
        return (availWidth, self._height)

    def draw(self):
        c   = self.canv
        y0  = self.bottom_space
        bar_h = self.font_size * 1.4

        # left accent bar
        c.setFillColor(ACCENT_NAVY)
        c.rect(0, y0, 3, bar_h, fill=1, stroke=0)

        # heading text
        c.setFillColor(INK_PRIMARY)
        c.setFont("Helvetica-Bold", self.font_size)
        text_x = 10
        text_y = y0 + (bar_h - self.font_size) / 2 + 1
        c.drawString(text_x, text_y, self.text)

        # hairline rule from end of text to right margin
        text_w = c.stringWidth(self.text, "Helvetica-Bold", self.font_size)
        rule_x = text_x + text_w + 8
        rule_y = y0 + bar_h / 2
        c.setStrokeColor(HAIRLINE)
        c.setLineWidth(0.5)
        c.line(rule_x, rule_y, self._w, rule_y)


class CoverBand(Flowable):
    """
    Full-width dark navy cover banner containing title, subtitle,
    classification badge and a decorative bottom rule.
    """
    def __init__(self, title, subtitle, available_width):
        super().__init__()
        self.title  = title
        self.subtitle = subtitle
        self._aw    = available_width
        self._h     = 2.4 * inch

    def wrap(self, availWidth, availHeight):
        return (self._aw, self._h)

    def draw(self):
        c  = self.canv
        w  = self._aw
        h  = self._h

        # background
        c.setFillColor(COVER_BG)
        c.rect(0, 0, w, h, fill=1, stroke=0)

        # bottom accent rule (3-tone gradient simulation via stacked rects)
        c.setFillColor(colors.HexColor("#2D5F9A"))
        c.rect(0, 0, w, 4, fill=1, stroke=0)
        c.setFillColor(colors.HexColor("#1A4A7A"))
        c.rect(0, 4, w, 2, fill=1, stroke=0)

        # subtle diagonal-grid texture lines (very low opacity via grey)
        c.setStrokeColor(colors.HexColor("#244F7A"))
        c.setLineWidth(0.4)
        step = 28
        for i in range(-int(h / step) - 2, int(w / step) + 2):
            x1 = i * step
            c.line(x1, 0, x1 + h, h)

        # IVDF monogram box  (top-left corner)
        c.setFillColor(colors.HexColor("#2D5F9A"))
        c.rect(20, h - 44, 36, 28, fill=1, stroke=0)
        c.setFillColor(INK_REVERSED)
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(38, h - 33, "IVDF")

        # main title
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(20, h - 78, self.title)

        # subtitle
        c.setFillColor(colors.HexColor("#93C5FD"))   # soft blue tint
        c.setFont("Helvetica", 10)
        c.drawString(20, h - 98, self.subtitle)

        # thin rule below subtitle
        c.setStrokeColor(colors.HexColor("#2D5F9A"))
        c.setLineWidth(0.75)
        c.line(20, h - 108, w - 20, h - 108)

        # classification tag
        tag_w, tag_h = 96, 16
        tag_x = w - tag_w - 20
        tag_y = h - 36
        c.setFillColor(colors.HexColor("#7F1D1D"))
        c.roundRect(tag_x, tag_y, tag_w, tag_h, 3, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(tag_x + tag_w / 2, tag_y + 5, "CONFIDENTIAL")

        # report label (bottom-right of banner)
        c.setFillColor(colors.HexColor("#93C5FD"))
        c.setFont("Helvetica", 8)
        c.drawRightString(w - 20, 12, "Vulnerability Assessment Report")


class SeverityPill(Flowable):
    """
    Refined pill badge — soft background, muted border, no harsh colours.
    Designed to sit inline inside a Table cell.
    """
    def __init__(self, label, pill_w=64, pill_h=15):
        super().__init__()
        self.label   = label.upper()
        self.pill_w  = pill_w
        self.pill_h  = pill_h

    def wrap(self, aw, ah):
        return (self.pill_w, self.pill_h)

    def draw(self):
        c      = self.canv
        ink    = SEV_INK.get(self.label,    INK_SECONDARY)
        bg     = SEV_BG.get(self.label,     SURFACE_1)
        border = SEV_BORDER.get(self.label, HAIRLINE)
        r      = self.pill_h / 2

        c.setFillColor(bg)
        c.roundRect(0, 0, self.pill_w, self.pill_h, r, fill=1, stroke=0)
        c.setStrokeColor(border)
        c.setLineWidth(0.6)
        c.roundRect(0, 0, self.pill_w, self.pill_h, r, fill=0, stroke=1)
        c.setFillColor(ink)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(self.pill_w / 2, 4.5, self.label)


class CardTopRule(Flowable):
    """A 3pt coloured rule that forms the top edge of a vulnerability card."""
    def __init__(self, color, width):
        super().__init__()
        self.rule_color = color
        self._w = width

    def wrap(self, aw, ah):
        return (self._w, 3)

    def draw(self):
        self.canv.setFillColor(self.rule_color)
        self.canv.rect(0, 0, self._w, 3, fill=1, stroke=0)


# ══════════════════════════════════════════════════════
#  PAGE CHROME  (header / footer drawn on every page)
# ══════════════════════════════════════════════════════

def _page_chrome(canvas, doc):
    """Elegant header + footer on every page."""
    w, h   = letter
    lm     = 0.65 * inch
    rm     = w - 0.65 * inch

    canvas.saveState()

    # ── top hairline ──────────────────────────────────
    canvas.setStrokeColor(HAIRLINE)
    canvas.setLineWidth(0.5)
    canvas.line(lm, h - 28, rm, h - 28)

    # ── header: page label left, page number right ────
    canvas.setFillColor(INK_TERTIARY)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(lm, h - 22, "IVDF  ·  Vulnerability Assessment Report")
    canvas.drawRightString(rm, h - 22, f"Page {doc.page}")

    # ── footer hairline ───────────────────────────────
    canvas.setStrokeColor(HAIRLINE)
    canvas.line(lm, 40, rm, 40)

    # ── footer text ───────────────────────────────────
    canvas.setFillColor(INK_TERTIARY)
    canvas.setFont("Helvetica-Oblique", 7)
    canvas.drawString(
        lm, 28,
        "CONFIDENTIAL  —  For authorised security assessment use only.  "
        "Generated by the Intelligent Vulnerability Detection and Analysis Framework."
    )

    canvas.restoreState()


# ══════════════════════════════════════════════════════
#  TYPOGRAPHY SYSTEM
# ══════════════════════════════════════════════════════

def _build_styles() -> dict:
    def ps(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    return {
        # ── cover (unused — CoverBand draws its own text) ──
        "cover_title": ps(
            "CoverTitle",
            fontName="Helvetica-Bold", fontSize=22,
            textColor=colors.white, alignment=TA_LEFT, leading=28,
        ),

        # ── scan details / metadata ──────────────────────
        "meta_label": ps(
            "MetaLabel",
            fontName="Helvetica-Bold", fontSize=8.5,
            textColor=INK_SECONDARY, leading=12,
        ),
        "meta_value": ps(
            "MetaValue",
            fontName="Helvetica", fontSize=8.5,
            textColor=INK_PRIMARY, leading=12, wordWrap="CJK",
        ),
        "meta_value_bold": ps(
            "MetaValueBold",
            fontName="Helvetica-Bold", fontSize=8.5,
            textColor=INK_PRIMARY, leading=12,
        ),

        # ── severity summary ────────────────────────────
        "sev_header": ps(
            "SevHeader",
            fontName="Helvetica-Bold", fontSize=8.5,
            textColor=colors.white, alignment=TA_CENTER,
        ),
        "sev_label": ps(
            "SevLabel",
            fontName="Helvetica-Bold", fontSize=8.5,
            textColor=INK_SECONDARY, leading=12,
        ),
        "sev_count": ps(
            "SevCount",
            fontName="Helvetica-Bold", fontSize=9,
            textColor=INK_PRIMARY, alignment=TA_CENTER, leading=12,
        ),

        # ── vulnerability cards ─────────────────────────
        "vuln_index": ps(
            "VulnIndex",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=INK_SECONDARY,
        ),
        "vuln_title": ps(
            "VulnTitle",
            fontName="Helvetica-Bold", fontSize=11,
            textColor=INK_PRIMARY, leading=15, spaceAfter=2,
        ),
        "field_label": ps(
            "FieldLabel",
            fontName="Helvetica-Bold", fontSize=7.5,
            textColor=INK_TERTIARY, leading=11,
            # letter-spacing simulated via spaces — ReportLab has no tracking
        ),
        "field_value": ps(
            "FieldValue",
            fontName="Helvetica", fontSize=8.5,
            textColor=INK_PRIMARY, leading=13, wordWrap="CJK",
        ),
        "field_value_mono": ps(
            "FieldValueMono",
            fontName="Courier", fontSize=8,
            textColor=INK_SECONDARY, leading=12, wordWrap="CJK",
        ),
        "bullet_item": ps(
            "BulletItem",
            fontName="Helvetica", fontSize=8.5,
            textColor=INK_PRIMARY, leading=13,
            leftIndent=10, spaceAfter=1, wordWrap="CJK",
        ),
        "ref_value": ps(
            "RefValue",
            fontName="Helvetica", fontSize=8,
            textColor=INK_ACCENT, leading=12, wordWrap="CJK",
        ),
    }


# ══════════════════════════════════════════════════════
#  TABLE BUILDERS
# ══════════════════════════════════════════════════════

_BASE_TABLE_STYLE = [
    # zero outer border — rely on HAIRLINE box
    ("BOX",           (0, 0), (-1, -1), 0.5, HAIRLINE),
    ("INNERGRID",     (0, 0), (-1, -1), 0.4, DIVIDER),
    ("TOPPADDING",    (0, 0), (-1, -1), 7),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
]


def _scan_details_table(metadata: dict, styles: dict, col_w: float) -> Table:
    """
    Two-column scan details table.
    Left column = small-caps style label (bold slate)
    Right column = value (near-black)
    Alternating row tint — no harsh borders.
    """
    label_map = [
        ("target",     "Target"),
        ("scan_id",    "Scan ID"),
        ("scan_type",  "Scan Type"),
        ("started",    "Started"),
        ("completed",  "Completed"),
        ("duration",   "Duration"),
        ("risk_score", "Risk Score"),
        ("generated",  "Generated"),
    ]

    rows = []
    for key, display in label_map:
        val = metadata.get(key, metadata.get(display, "—"))

        # risk score gets special bold colouring
        if key == "risk_score":
            risk = float(val) if str(val).replace(".", "").isdigit() else 0
            ink  = (SEV_INK["CRITICAL"] if risk >= 9
                    else SEV_INK["HIGH"]   if risk >= 7
                    else SEV_INK["MEDIUM"] if risk >= 4
                    else INK_PRIMARY)
            val_para = Paragraph(
                f'<font color="{ink.hexval()}"><b>{val}</b></font>',
                styles["meta_value"]
            )
        else:
            val_para = Paragraph(str(val), styles["meta_value"])

        rows.append([
            Paragraph(display, styles["meta_label"]),
            val_para,
        ])

    cw   = [1.5 * inch, col_w - 1.5 * inch]
    tbl  = Table(rows, colWidths=cw)
    cmds = list(_BASE_TABLE_STYLE) + [
        ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_0),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [SURFACE_0, SURFACE_1]),
        # label column: lighter background
        ("BACKGROUND",    (0, 0), (0, -1),  SURFACE_1),
    ]
    tbl.setStyle(TableStyle(cmds))
    return tbl


def _severity_summary_table(summary: dict, styles: dict, col_w: float) -> Table:
    """
    Severity summary: dark header row + subtle alternating body rows.
    Counts are right-aligned and bold.
    """
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    header = [
        Paragraph("Severity Level", styles["sev_header"]),
        Paragraph("Count", styles["sev_header"]),
    ]
    rows = [header]

    for sev in order:
        count = int(summary.get(sev, summary.get(sev.title(), 0)))
        ink   = SEV_INK.get(sev, INK_SECONDARY)
        bg    = SEV_BG.get(sev, SURFACE_1)
        rows.append([
            Paragraph(
                f'<font color="{ink.hexval()}"><b>{sev}</b></font>',
                styles["meta_label"]
            ),
            Paragraph(
                f'<font color="{ink.hexval()}"><b>{count}</b></font>',
                styles["sev_count"]
            ),
        ])

    cw   = [col_w - 1.5 * inch, 1.5 * inch]
    tbl  = Table(rows, colWidths=cw)
    cmds = list(_BASE_TABLE_STYLE) + [
        # header band
        ("BACKGROUND",    (0, 0), (-1, 0),  SURFACE_HEADER),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        # body
        ("BACKGROUND",    (0, 1), (-1, -1), SURFACE_0),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [SURFACE_0, SURFACE_1]),
        ("ALIGN",         (1, 0), (1, -1),  "CENTER"),
        # no inner grid for cleaner look — keep only horizontal lines
        ("INNERGRID",     (0, 0), (-1, -1), 0, colors.transparent),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.4, DIVIDER),
        ("BOX",           (0, 0), (-1, -1), 0.5, HAIRLINE),
    ]
    tbl.setStyle(TableStyle(cmds))
    return tbl


def _meta_row_table(pairs: list, styles: dict, col_w: float) -> Table:
    """
    Horizontal key-value strip used inside vulnerability cards.
    pairs = [ (label, value), ... ]
    """
    label_cells = [Paragraph(lbl, styles["field_label"])  for lbl, _ in pairs]
    value_cells = [Paragraph(str(val), styles["field_value_mono"]) for _, val in pairs]

    n    = len(pairs)
    unit = col_w / n
    cw   = [unit] * n
    tbl  = Table([label_cells, value_cells], colWidths=cw)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_1),
        ("BOX",           (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("INNERGRID",     (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return tbl


def _detail_table(rows_data: list, styles: dict, col_w: float) -> Table:
    """
    Two-column label | content table inside vulnerability cards.
    rows_data = [ (label_str, paragraph_or_list_of_paragraphs), ... ]
    """
    rows = []
    for lbl, content in rows_data:
        label_para = Paragraph(lbl.upper(), styles["field_label"])
        if isinstance(content, list):
            # list of bullet strings
            body = [
                Paragraph(f"&#x2022;  {item}", styles["bullet_item"])
                for item in content
            ]
        else:
            body = [Paragraph(str(content), styles["field_value"])]
        rows.append([label_para, body])

    lw  = 0.85 * inch
    cw  = [lw, col_w - lw]
    tbl = Table(rows, colWidths=cw)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_0),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [SURFACE_0, SURFACE_1]),
        ("BOX",           (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.3, DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        # label column slightly dimmer
        ("BACKGROUND",    (0, 0), (0, -1),  SURFACE_1),
    ]))
    return tbl


# ══════════════════════════════════════════════════════
#  VULNERABILITY CARD
# ══════════════════════════════════════════════════════

def _vuln_card(idx: int, vuln: dict, styles: dict, card_w: float) -> KeepTogether:
    """
    Build a self-contained, elegantly styled vulnerability card.

    Structure:
      ┌─── 3pt severity colour rule ─────────────────────┐
      │  #N  VULNERABILITY NAME            [SEVERITY PILL] │
      │  ─ meta strip: OWASP | CVSS | Affected ──────────  │
      │  ─ detail rows: Explanation / Impact / Remediation  │
      └───────────────────────────────────────────────────┘
    """
    sev      = vuln.get("severity", "INFO").upper()
    rule_col = SEV_RULE.get(sev, INK_TERTIARY)
    ink      = SEV_INK.get(sev, INK_SECONDARY)

    elems = []

    # ── top colour rule ───────────────────────────────
    elems.append(CardTopRule(rule_col, card_w))

    # ── title row ─────────────────────────────────────
    pill  = SeverityPill(sev, pill_w=58, pill_h=14)

    title_row = Table(
        [[
            Paragraph(
                f'<font color="{INK_TERTIARY.hexval()}" size="8">#{idx:02d}</font>   '
                f'<b>{vuln.get("name", "Unknown Vulnerability")}</b>',
                styles["vuln_title"]
            ),
            pill,
        ]],
        colWidths=[card_w - 0.85 * inch, 0.75 * inch],
    )
    title_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_0),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (1, 0),   "RIGHT"),
    ]))
    elems.append(title_row)

    # ── meta strip ────────────────────────────────────
    owasp    = vuln.get("owasp", "—")
    cvss     = str(vuln.get("cvss", vuln.get("cvss_score", "—")))
    affected = str(vuln.get("affected", vuln.get("port", vuln.get("url", "—"))))

    meta_pairs = [
        ("OWASP MAPPING", owasp),
        ("CVSS SCORE",    cvss),
        ("AFFECTED",      affected),
    ]
    elems.append(_meta_row_table(meta_pairs, styles, card_w))

    # ── detail rows ───────────────────────────────────
    detail_rows = []

    explanation = vuln.get("explanation", vuln.get("description", ""))
    if explanation:
        detail_rows.append(("Explanation", explanation))

    impact = vuln.get("impact", "")
    if impact:
        detail_rows.append(("Impact", impact))

    remediation = vuln.get("remediation", vuln.get("fix", []))
    if remediation:
        if isinstance(remediation, str):
            remediation = [remediation]
        detail_rows.append(("Remediation", remediation))

    references = vuln.get("references", vuln.get("refs", ""))
    if references:
        detail_rows.append(("References", references))

    if detail_rows:
        elems.append(_detail_table(detail_rows, styles, card_w))

    # ── bottom spacer ─────────────────────────────────
    elems.append(Spacer(1, 16))

    return KeepTogether(elems)


# ══════════════════════════════════════════════════════
#  REPORT GENERATOR  (public API)
# ══════════════════════════════════════════════════════

class ReportGenerator:
    """
    IVDF Report Generator — PDF, JSON, CSV output.

    Usage
    -----
    rg = ReportGenerator()
    rg.generate_pdf("scan_report", data)
    rg.generate_json("scan_report", data)
    rg.generate_csv("scan_report", data)

    Expected data schema
    --------------------
    {
        "metadata": {
            "target":     "127.0.0.1",
            "scan_id":    "913ee222-...",
            "scan_type":  "normal",
            "started":    "2026-05-24T09:37:13",
            "completed":  "2026-05-24T09:40:44",
            "duration":   "211.4s",
            "risk_score": 9.8,
            "generated":  "2026-05-24 09:45 UTC",
        },
        "severity_summary": {
            "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        },
        "vulnerabilities": [
            {
                "name":        "...",
                "severity":    "CRITICAL",
                "owasp":       "OWASP A06:2021 – ...",
                "cvss":        9.8,
                "affected":    "445",
                "explanation": "...",
                "impact":      "...",
                "remediation": ["step 1", "step 2"],
                "references":  "CVE-...",
            }
        ],
    }
    """

    OUTPUT_DIR = "generated_reports"

    # ── internal ──────────────────────────────────────
    def _ensure_dir(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    # ── PDF ───────────────────────────────────────────
    def generate_pdf(self, filename: str, data: dict) -> str:
        self._ensure_dir()
        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.pdf")
        styles   = _build_styles()

        # ── page geometry ─────────────────────────────
        lm = rm = 0.65 * inch
        tm = bm = 0.70 * inch
        pw, ph  = letter
        body_w  = pw - lm - rm   # usable content width ≈ 7.2 inch

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            leftMargin=lm, rightMargin=rm,
            topMargin=tm,  bottomMargin=bm,
            title="Vulnerability Assessment Report",
            author="IVDF",
        )

        story = []

        # ── COVER BAND ────────────────────────────────
        story.append(CoverBand(
            title    = "Vulnerability Assessment Report",
            subtitle = "Intelligent Vulnerability Detection and Analysis Framework",
            available_width = body_w,
        ))
        story.append(Spacer(1, 24))

        # ── SCAN DETAILS ──────────────────────────────
        story.append(SectionRule("Scan Details"))
        story.append(_scan_details_table(data.get("metadata", {}), styles, body_w))
        story.append(Spacer(1, 22))

        # ── SEVERITY SUMMARY ──────────────────────────
        story.append(SectionRule("Severity Summary"))

        # render summary half-width, centred — looks premium on a wide page
        half_w = body_w * 0.55
        pad_w  = (body_w - half_w) / 2
        sev_tbl = _severity_summary_table(
            data.get("severity_summary", {}), styles, half_w
        )
        outer = Table([[sev_tbl]], colWidths=[body_w])
        outer.setStyle(TableStyle([
            ("LEFTPADDING",  (0, 0), (-1, -1), pad_w),
            ("RIGHTPADDING", (0, 0), (-1, -1), pad_w),
            ("TOPPADDING",   (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
        ]))
        story.append(outer)
        story.append(Spacer(1, 26))

        # ── VULNERABILITY FINDINGS ────────────────────
        vulns = data.get("vulnerabilities", [])
        if vulns:
            story.append(SectionRule("Vulnerability Findings"))
            story.append(Spacer(1, 8))
            for idx, vuln in enumerate(vulns, start=1):
                story.append(_vuln_card(idx, vuln, styles, body_w))

        # ── BUILD ─────────────────────────────────────
        doc.build(
            story,
            onFirstPage  = _page_chrome,
            onLaterPages = _page_chrome,
        )
        return filepath

    # ── JSON ──────────────────────────────────────────
    def generate_json(self, filename: str, data: dict) -> str:
        self._ensure_dir()
        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        return filepath

    # ── CSV ───────────────────────────────────────────
    def generate_csv(self, filename: str, data: dict) -> str:
        self._ensure_dir()
        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.csv")

        metadata = data.get("metadata", {})
        vulns    = data.get("vulnerabilities", [])

        fieldnames = [
            "scan_target", "scan_id", "scan_type", "started", "completed",
            "duration", "risk_score", "generated",
            "vuln_index", "name", "severity", "owasp", "cvss",
            "affected", "explanation", "impact", "remediation", "references",
        ]

        rows = []
        for idx, vuln in enumerate(vulns, start=1):
            fix = vuln.get("remediation", vuln.get("fix", []))
            if isinstance(fix, list):
                fix = " | ".join(fix)
            rows.append({
                "scan_target":  metadata.get("target",     ""),
                "scan_id":      metadata.get("scan_id",    ""),
                "scan_type":    metadata.get("scan_type",  ""),
                "started":      metadata.get("started",    ""),
                "completed":    metadata.get("completed",  ""),
                "duration":     metadata.get("duration",   ""),
                "risk_score":   metadata.get("risk_score", ""),
                "generated":    metadata.get("generated",  ""),
                "vuln_index":   idx,
                "name":         vuln.get("name",        ""),
                "severity":     vuln.get("severity",    ""),
                "owasp":        vuln.get("owasp",       ""),
                "cvss":         vuln.get("cvss",        vuln.get("cvss_score", "")),
                "affected":     vuln.get("affected",    vuln.get("port", "")),
                "explanation":  vuln.get("explanation", vuln.get("description", "")),
                "impact":       vuln.get("impact",      ""),
                "remediation":  fix,
                "references":   vuln.get("references",  ""),
            })

        if not rows:
            rows.append({k: "" for k in fieldnames})

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        return filepath


# ══════════════════════════════════════════════════════
#  SMOKE TEST
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    sample_data = {
        "metadata": {
            "target":     "127.0.0.1",
            "scan_id":    "913ee222-2a55-4ca4-9475-88db28ccf774",
            "scan_type":  "normal",
            "started":    "2026-05-24T09:37:13.248880",
            "completed":  "2026-05-24T09:40:44.741772",
            "duration":   "211.4s",
            "risk_score": 9.8,
            "generated":  "2026-05-24 09:45 UTC",
        },
        "severity_summary": {
            "CRITICAL": 1,
            "HIGH":     2,
            "MEDIUM":   3,
            "LOW":      1,
            "INFO":     0,
        },
        "vulnerabilities": [
            {
                "name":     "Dangerous Open Port: 445/SMB",
                "severity": "CRITICAL",
                "owasp":    "OWASP A06:2021 \u2013 Security Misconfiguration",
                "cvss":     9.8,
                "affected": "445",
                "explanation": (
                    "Port 445 (SMB) is exposed to the network without firewall "
                    "restrictions. This service allows remote file sharing and is "
                    "a frequent target for automated exploits including EternalBlue."
                ),
                "impact": "EternalBlue / WannaCry ransomware attack surface. "
                          "Unauthenticated remote code execution is possible.",
                "remediation": [
                    "Close port 445 if the service is not required.",
                    "Restrict access via firewall rules to trusted IPs only.",
                    "Place the service behind a VPN or bastion host.",
                    "Enable authentication and encryption for the SMB service.",
                    "Apply MS17-010 patch and all subsequent security updates.",
                ],
                "references": "CVE-2017-0144  |  MS17-010  |  NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            },
            {
                "name":     "Outdated TLS Version: TLS 1.0 / 1.1 Enabled",
                "severity": "HIGH",
                "owasp":    "OWASP A02:2021 \u2013 Cryptographic Failures",
                "cvss":     7.4,
                "affected": "443/tcp (HTTPS)",
                "explanation": (
                    "The server accepts connections using deprecated TLS 1.0 and TLS 1.1 "
                    "protocols. These versions are vulnerable to BEAST, POODLE, and other "
                    "known cipher downgrade attacks."
                ),
                "impact": "Man-in-the-middle attacks may allow decryption of sensitive traffic.",
                "remediation": [
                    "Disable TLS 1.0 and TLS 1.1 at the server and load-balancer level.",
                    "Enforce TLS 1.2 as minimum with strong cipher suites.",
                    "Prefer TLS 1.3 where client compatibility allows.",
                ],
                "references": "NIST SP 800-52 Rev. 2  |  RFC 8996",
            },
        ],
    }

    rg = ReportGenerator()
    pdf  = rg.generate_pdf ("report_v2_demo", sample_data)
    j    = rg.generate_json("report_v2_demo", sample_data)
    csv_ = rg.generate_csv ("report_v2_demo", sample_data)
    print(f"PDF  → {pdf}")
    print(f"JSON → {j}")
    print(f"CSV  → {csv_}")