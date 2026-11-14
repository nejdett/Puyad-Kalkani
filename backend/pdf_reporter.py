from __future__ import annotations

import io
import platform
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import database
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.fonts import addMapping
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

FONT_NAME = "DejaVuSans"
FONT_BOLD = "DejaVuSans-Bold"
_FONT_REGISTERED = False


def _register_fonts() -> None:
    global _FONT_REGISTERED
    if _FONT_REGISTERED:
        return
    _FONT_REGISTERED = True
    project_dir = Path(__file__).parent / "fonts"
    local_regular = project_dir / "DejaVuSans.ttf"
    local_bold = project_dir / "DejaVuSans-Bold.ttf"
    if local_regular.exists():
        pdfmetrics.registerFont(TTFont(FONT_NAME, str(local_regular)))
        if local_bold.exists():
            pdfmetrics.registerFont(TTFont(FONT_BOLD, str(local_bold)))
        else:
            pdfmetrics.registerFont(TTFont(FONT_BOLD, str(local_regular)))
        addMapping(FONT_NAME, 0, 0, FONT_NAME)
        addMapping(FONT_NAME, 1, 0, FONT_BOLD)
        return
    candidates = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
         "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf"),
        ("/usr/share/fonts/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf"),
    ]
    for regular, bold in candidates:
        if Path(regular).exists():
            pdfmetrics.registerFont(TTFont(FONT_NAME, regular))
            if Path(bold).exists():
                pdfmetrics.registerFont(TTFont(FONT_BOLD, bold))
            else:
                pdfmetrics.registerFont(TTFont(FONT_BOLD, regular))
            addMapping(FONT_NAME, 0, 0, FONT_NAME)
            addMapping(FONT_NAME, 1, 0, FONT_BOLD)
            return
    _FONT_REGISTERED = False


_register_fonts()


def _font(bold: bool = False) -> str:
    if _FONT_REGISTERED:
        return FONT_BOLD if bold else FONT_NAME
    return "Helvetica-Bold" if bold else "Helvetica"


C_PRIMARY: Any     = colors.HexColor("#1e3a5f")
C_PRIMARY_LT: Any  = colors.HexColor("#2563eb")
C_PRIMARY_XLT: Any = colors.HexColor("#dbeafe")
C_SUCCESS: Any     = colors.HexColor("#059669")
C_SUCCESS_BG: Any  = colors.HexColor("#d1fae5")
C_WARNING: Any     = colors.HexColor("#d97706")
C_WARNING_BG: Any  = colors.HexColor("#fef3c7")
C_DANGER: Any      = colors.HexColor("#dc2626")
C_DANGER_BG: Any   = colors.HexColor("#fee2e2")
C_BORDER: Any      = colors.HexColor("#e2e8f0")
C_TEXT: Any        = colors.HexColor("#1e293b")
C_TEXT_SEC: Any    = colors.HexColor("#475569")
C_MUTED: Any       = colors.HexColor("#94a3b8")
C_WHITE: Any       = colors.white
C_TBL_HEADER: Any  = colors.HexColor("#1e3a5f")
C_TBL_ROW: Any     = colors.HexColor("#f8fafc")


def _score_color(score: int) -> Any:
    if score >= 80: return C_SUCCESS
    if score >= 50: return C_WARNING
    return C_DANGER


def _score_bg(score: int) -> Any:
    if score >= 80: return C_SUCCESS_BG
    if score >= 50: return C_WARNING_BG
    return C_DANGER_BG


def _score_label(score: int) -> str:
    if score >= 80: return "İYİ"
    if score >= 50: return "ORTA"
    return "KRİTİK"


def _styles() -> dict[str, ParagraphStyle]:
    return {
        "title": ParagraphStyle("title", fontName=_font(True), fontSize=22,
                                textColor=C_PRIMARY, leading=28),
        "subtitle": ParagraphStyle("subtitle", fontName=_font(), fontSize=10,
                                   textColor=C_TEXT_SEC, leading=14),
        "section": ParagraphStyle("section", fontName=_font(True), fontSize=12,
                                  textColor=C_PRIMARY, spaceBefore=10, spaceAfter=6, leading=16),
        "label": ParagraphStyle("label", fontName=_font(), fontSize=7,
                                textColor=C_MUTED, leading=9),
        "value": ParagraphStyle("value", fontName=_font(True), fontSize=8,
                                textColor=C_TEXT, leading=11),
        "cell": ParagraphStyle("cell", fontName=_font(), fontSize=7.5,
                               textColor=C_TEXT, leading=10),
        "cell_bold": ParagraphStyle("cellb", fontName=_font(True), fontSize=7.5,
                                    textColor=C_TEXT, leading=10),
        "cell_hdr": ParagraphStyle("cellh", fontName=_font(True), fontSize=7.5,
                                   textColor=C_WHITE, leading=10),
        "cell_ok": ParagraphStyle("cellok", fontName=_font(True), fontSize=7.5,
                                  textColor=C_SUCCESS, leading=10, alignment=TA_CENTER),
        "cell_fail": ParagraphStyle("cellfl", fontName=_font(True), fontSize=7.5,
                                    textColor=C_DANGER, leading=10, alignment=TA_CENTER),
        "center": ParagraphStyle("center", fontName=_font(), fontSize=7.5,
                                 textColor=C_TEXT, leading=10, alignment=TA_CENTER),
        "small": ParagraphStyle("small", fontName=_font(), fontSize=7,
                                textColor=C_MUTED, leading=10, alignment=TA_JUSTIFY),
    }


def _section_hdr(title: str, s: dict[str, ParagraphStyle], width: float) -> Table:
    data = [[
        "",
        Paragraph(title, s["section"]),
    ]]
    t = Table(data, colWidths=[4, width - 4])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), C_PRIMARY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 6),
    ]))
    return t


def _score_gauge(score: int, width: float) -> Drawing:
    d = Drawing(width, 26)
    bar_h = 14
    y = 6
    bg = Rect(0, y, width, bar_h, rx=7, ry=7)
    bg.fillColor = C_BORDER
    bg.strokeColor = None
    d.add(bg)
    fill_w = max(14, width * score / 100)
    bar = Rect(0, y, fill_w, bar_h, rx=7, ry=7)
    bar.fillColor = _score_color(score)
    bar.strokeColor = None
    d.add(bar)
    d.add(String(width / 2, y + 3, f"{score}/100",
                 fontSize=9, fillColor=C_WHITE, textAnchor="middle", fontName=_font(True)))
    d.add(String(0, y - 9, "0", fontSize=6, fillColor=C_MUTED, textAnchor="start", fontName=_font()))
    d.add(String(width, y - 9, "100", fontSize=6, fillColor=C_MUTED, textAnchor="end", fontName=_font()))
    return d


def _table_style(row_count: int, header_pad: int, extra: list[Any]) -> TableStyle:
    styles: list[Any] = [
        ("BACKGROUND", (0, 0), (-1, 0), C_TBL_HEADER),
        ("TOPPADDING", (0, 0), (-1, 0), header_pad),
        ("BOTTOMPADDING", (0, 0), (-1, 0), header_pad),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        *extra,
        ("LINEBELOW", (0, 0), (-1, 0), 1, C_PRIMARY),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, C_BORDER),
        ("LINEAFTER", (0, 0), (-2, -1), 0.3, C_BORDER),
    ]
    styles += [("BACKGROUND", (0, i), (-1, i), C_TBL_ROW) for i in range(2, row_count, 2)]
    return TableStyle(styles)


def _category_chart(cat_stats: dict[str, dict[str, int]], width: float) -> Any:
    cats = list(cat_stats.items())
    if not cats:
        return Spacer(1, 1)

    max_val = max((v["total"] for _, v in cats), default=1)

    hdr_style = ParagraphStyle("ch", fontName=_font(True), fontSize=7,
                               textColor=C_WHITE, leading=9)
    cell_style = ParagraphStyle("cc", fontName=_font(), fontSize=7,
                                textColor=C_TEXT, leading=9)
    bar_label = ParagraphStyle("cb", fontName=_font(True), fontSize=7,
                               textColor=C_TEXT, leading=9, alignment=TA_CENTER)

    data: list[list[Any]] = [[
        Paragraph("KATEGORİ", hdr_style),
        Paragraph("GÜVENLİ", hdr_style),
        Paragraph("UYARI", hdr_style),
        Paragraph("TOPLAM", hdr_style),
    ]]

    bar_area = width * 0.45

    for cat, vals in cats:
        display = cat if len(cat) <= 22 else cat[:20] + "…"

        ok_w = max(2, (vals["ok"] / max_val) * bar_area) if max_val else 2
        fail_w = max(2, (vals["fail"] / max_val) * bar_area) if max_val else 2

        ok_bar = Drawing(ok_w, 10)
        ok_r = Rect(0, 0, ok_w, 10, rx=3, ry=3)
        ok_r.fillColor = C_SUCCESS
        ok_r.strokeColor = None
        ok_bar.add(ok_r)

        fail_bar = Drawing(fail_w, 10)
        fail_r = Rect(0, 0, fail_w, 10, rx=3, ry=3)
        fail_r.fillColor = C_DANGER
        fail_r.strokeColor = None
        fail_bar.add(fail_r)

        data.append([
            Paragraph(escape(display), cell_style),
            ok_bar,
            fail_bar,
            Paragraph(str(vals["total"]), bar_label),
        ])

    col_widths = [width * 0.25, width * 0.25, width * 0.25, width * 0.12]
    t = Table(data, colWidths=col_widths, repeatRows=1)

    t.setStyle(_table_style(len(data), 5, [("ALIGN", (3, 0), (3, -1), "CENTER"), ("ROUNDEDCORNERS", [4, 4, 0, 0])]))
    return t


def _results_table(scan_results: list[dict[str, Any]], s: dict[str, ParagraphStyle], width: float) -> Table:
    data: list[list[Any]] = [[
        Paragraph("#", s["cell_hdr"]),
        Paragraph("KURAL ADI", s["cell_hdr"]),
        Paragraph("DURUM", s["cell_hdr"]),
    ]]
    for i, r in enumerate(scan_results, 1):
        name = r.get("rule_name", r.get("rule_id", "-"))[:65]
        is_ok = r["status"] == "ok"
        data.append([
            Paragraph(str(i), s["center"]),
            Paragraph(escape(name), s["cell"]),
            Paragraph("✓ Güvenli" if is_ok else "✗ Uyarı", s["cell_ok"] if is_ok else s["cell_fail"]),
        ])

    cw = [0.8 * cm, width - 3.8 * cm, 3 * cm]
    t = Table(data, colWidths=cw, repeatRows=1)
    t.setStyle(_table_style(len(data), 6, [("ALIGN", (0, 0), (0, -1), "CENTER"), ("ALIGN", (2, 0), (2, -1), "CENTER")]))
    return t


def _fixes_table(fixes: list[dict[str, Any]], s: dict[str, ParagraphStyle], width: float) -> Table:
    data: list[list[Any]] = [[
        Paragraph("TARİH", s["cell_hdr"]),
        Paragraph("KURAL", s["cell_hdr"]),
        Paragraph("DURUM", s["cell_hdr"]),
    ]]
    for f in fixes[:20]:
        dt = f.get("created_at", "-")
        if dt and dt != "-":
            try:
                dt = datetime.fromisoformat(dt).strftime("%d.%m.%Y %H:%M")
            except Exception:
                pass
        is_ok = f["status"] == "success"
        data.append([
            Paragraph(escape(str(dt)), s["cell"]),
            Paragraph(escape(f.get("rule_name", "-")[:55]), s["cell"]),
            Paragraph("✓ Başarılı" if is_ok else "✗ Başarısız", s["cell_ok"] if is_ok else s["cell_fail"]),
        ])

    cw = [3.2 * cm, width - 5.7 * cm, 2.5 * cm]
    t = Table(data, colWidths=cw, repeatRows=1)
    t.setStyle(_table_style(len(data), 6, [("ALIGN", (2, 0), (2, -1), "CENTER")]))
    return t


def _trend_table(trend: list[dict[str, Any]], s: dict[str, ParagraphStyle]) -> Table:
    data: list[list[Any]] = [[
        Paragraph("#", s["cell_hdr"]),
        Paragraph("TARİH", s["cell_hdr"]),
        Paragraph("SKOR", s["cell_hdr"]),
        Paragraph("DURUM", s["cell_hdr"]),
    ]]
    for i, t_item in enumerate(trend, 1):
        dt = t_item.get("created_at", "-")
        try:
            dt = datetime.fromisoformat(dt).strftime("%d.%m.%Y %H:%M")
        except Exception:
            pass
        sc = t_item["score"]
        sc_hex: str = _score_color(sc).hexval()[2:]
        data.append([
            Paragraph(str(i), s["center"]),
            Paragraph(escape(str(dt)), s["center"]),
            Paragraph(f"<font color='#{sc_hex}'><b>{sc}</b></font>", s["center"]),
            Paragraph(_score_label(sc), s["center"]),
        ])

    cw = [1.2 * cm, 4.5 * cm, 2 * cm, 2.5 * cm]
    t = Table(data, colWidths=cw, repeatRows=1)
    t.setStyle(_table_style(len(data), 6, [("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    return t


def _first_page(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    w = A4[0]
    canvas.setFont(_font(), 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(1.5 * cm, 0.8 * cm,
                      "Bu rapor Puyad Kalkanı tarafından otomatik olarak oluşturulmuştur.")
    canvas.drawRightString(w - 1.5 * cm, 0.8 * cm, f"Sayfa {doc.page}")
    canvas.restoreState()


def _later_pages(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    w = A4[0]
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(1.5 * cm, 1.2 * cm, w - 1.5 * cm, 1.2 * cm)
    canvas.setFont(_font(), 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(1.5 * cm, 0.8 * cm,
                      f"Puyad Kalkanı v1.0.0 — {datetime.now().strftime('%d.%m.%Y')}")
    canvas.drawRightString(w - 1.5 * cm, 0.8 * cm, f"Sayfa {doc.page}")
    canvas.setFont(_font(True), 7)
    canvas.setFillColor(C_PRIMARY)
    canvas.drawRightString(w - 1.5 * cm, 1.5 * cm, "PUYAD KALKANI")
    canvas.restoreState()


def generate_report(scan_id: int | None = None) -> bytes:
    with database.get_connection() as conn:
        if scan_id:
            scan = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
        else:
            scan = conn.execute("SELECT * FROM scan_history ORDER BY created_at DESC LIMIT 1").fetchone()

        if not scan:
            scan = {"id": 0, "total": 0, "warnings": 0, "ok_count": 0,
                    "score": 0, "created_at": datetime.now().isoformat()}
            scan_results = []
        else:
            scan = dict(scan)
            scan_results = [dict(r) for r in conn.execute(
                "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY status", (scan["id"],)
            ).fetchall()]

        fixes = [dict(r) for r in conn.execute(
            "SELECT * FROM fix_history ORDER BY created_at DESC LIMIT 20").fetchall()]
        trend = [dict(r) for r in conn.execute(
            "SELECT score, created_at FROM scan_history ORDER BY created_at ASC LIMIT 10").fetchall()]

    cat_stats = {}
    for r in scan_results:
        cat = r.get("rule_name", "").split(" ")[0] if r.get("rule_name") else "Diğer"
        if cat not in cat_stats:
            cat_stats[cat] = {"ok": 0, "fail": 0, "total": 0}
        cat_stats[cat]["total"] += 1
        if r["status"] == "ok":
            cat_stats[cat]["ok"] += 1
        else:
            cat_stats[cat]["fail"] += 1

    score = scan.get("score", 0)
    report_date = datetime.now().strftime("%d.%m.%Y %H:%M")
    hostname = platform.node() or "Linux Sunucu"
    os_info = f"{platform.system()} {platform.release()}"

    buf = io.BytesIO()
    pw = A4[0] - 3 * cm

    doc = SimpleDocTemplate(buf, pagesize=A4,
                            rightMargin=1.5 * cm, leftMargin=1.5 * cm,
                            topMargin=1.5 * cm, bottomMargin=2 * cm,
                            title="Puyad Kalkanı Güvenlik Raporu",
                            author="Puyad Kalkanı v1.0.0")

    s = _styles()
    story: list[Any] = []

    banner_data = [[""]]
    banner = Table(banner_data, colWidths=[pw], rowHeights=[6])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), C_PRIMARY),
                                ("TOPPADDING", (0, 0), (-1, -1), 0),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    story.append(banner)
    story.append(Spacer(1, 10))

    title_data = [[
        Paragraph("PUYAD KALKANI", s["title"]),
        Paragraph(f"<font name='{_font()}' size='9' color='#94a3b8'>v1.0.0</font>",
                  ParagraphStyle("ver", alignment=TA_RIGHT, fontSize=9, fontName=_font())),
    ]]
    tt = Table(title_data, colWidths=[pw * 0.7, pw * 0.3])
    tt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    story.append(tt)
    story.append(Spacer(1, 3))
    story.append(Paragraph("Linux Güvenlik Sıkılaştırma ve Değerlendirme Raporu", s["subtitle"]))
    story.append(Spacer(1, 6))

    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    lbl = s["label"]
    val = s["value"]
    info = Table(
        [[Paragraph("RAPOR TARİHİ", lbl), Paragraph("SİSTEM", lbl),
          Paragraph("İŞLETİM SİSTEMİ", lbl), Paragraph("STANDART", lbl)],
         [Paragraph(report_date, val), Paragraph(escape(hostname[:22]), val),
          Paragraph(escape(os_info[:28]), val), Paragraph("CIS / NIST", val)]],
        colWidths=[pw / 4] * 4
    )
    info.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_PRIMARY_XLT),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, C_PRIMARY_LT),
    ]))
    story.append(info)
    story.append(Spacer(1, 14))

    story.append(_section_hdr("GÜVENLİK SKORU", s, pw))
    story.append(Spacer(1, 6))

    kw = (pw - 15) / 4
    sc = ParagraphStyle("sc", fontName=_font(True), fontSize=20, alignment=TA_CENTER, leading=24)
    sl = ParagraphStyle("sl", fontName=_font(), fontSize=7, textColor=C_MUTED, alignment=TA_CENTER, leading=9)

    ok_c = scan.get("ok_count", 0)
    warn_c = scan.get("warnings", 0)
    total_c = scan.get("total", 0)
    cards = Table([[
        Paragraph(f"<font color='#{_score_color(score).hexval()[2:]}'>{score}/100</font>", sc),
        Paragraph(f"<font color='#059669'>{ok_c}</font>", sc),
        Paragraph(f"<font color='#d97706'>{warn_c}</font>", sc),
        Paragraph(f"<font color='#1e3a5f'>{total_c}</font>", sc),
    ], [
        Paragraph("Skor", sl),
        Paragraph("Güvenli", sl),
        Paragraph("Uyarı", sl),
        Paragraph("Toplam", sl),
    ]], colWidths=[kw] * 4)

    card_styles: list[Any] = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
        ("LINEBELOW", (0, 0), (-1, 0), 0.3, C_BORDER),
    ]
    for i in range(4):
        bg = [_score_bg(score), C_SUCCESS_BG, C_WARNING_BG, C_PRIMARY_XLT][i]
        card_styles.append(("BACKGROUND", (i, 0), (i, -1), bg))
    cards.setStyle(TableStyle(card_styles))
    story.append(cards)
    story.append(Spacer(1, 8))

    story.append(_score_gauge(score, pw))
    story.append(Spacer(1, 10))

    if cat_stats:
        story.append(_section_hdr("KATEGORİ ANALİZİ", s, pw))
        story.append(Spacer(1, 4))
        story.append(_category_chart(cat_stats, pw))
        story.append(Spacer(1, 8))

    if scan_results:
        story.append(_section_hdr("KURAL TARAMA SONUÇLARI", s, pw))
        story.append(Spacer(1, 4))
        story.append(_results_table(scan_results, s, pw))
        story.append(Spacer(1, 8))

    if fixes:
        story.append(_section_hdr("SON DÜZELTME İŞLEMLERİ", s, pw))
        story.append(Spacer(1, 4))
        story.append(_fixes_table(fixes, s, pw))
        story.append(Spacer(1, 8))

    if len(trend) >= 2:
        story.append(_section_hdr("GÜVENLİK SKORU TRENDİ", s, pw))
        story.append(Spacer(1, 4))
        story.append(_trend_table(trend, s))
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))
    story.append(Paragraph(
        f"Bu rapor <b>Puyad Kalkanı v1.0.0</b> tarafından {report_date} tarihinde "
        "otomatik olarak oluşturulmuştur. CIS Benchmark ve NIST standartlarına göre "
        "değerlendirilmiştir.",
        s["small"]
    ))

    doc.build(story, onFirstPage=_first_page, onLaterPages=_later_pages)
    buf.seek(0)
    return buf.read()
