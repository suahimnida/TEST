import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas import ReportResponse

_FONT_DIR = Path(__file__).resolve().parents[2] / "resources" / "fonts"
_FONT, _FONT_BOLD = "NanumGothic", "NanumGothic-Bold"

INK = colors.HexColor("#1f2933")
MUTED = colors.HexColor("#616e7c")
LINE = colors.HexColor("#d9dee3")
PANEL = colors.HexColor("#f4f6f8")
LEVEL_COLORS = {
    "danger": colors.HexColor("#c62828"),
    "warning": colors.HexColor("#e65100"),
    "caution": colors.HexColor("#b28704"),
    "safe": colors.HexColor("#2e7d32"),
}
VERDICT_KO = {"phishing": "피싱", "suspicious": "의심", "normal": "정상"}
LEVEL_KO = {"safe": "안전", "caution": "주의", "warning": "경고", "danger": "위험"}
KST = timezone(timedelta(hours=9))


def _register_fonts() -> None:
    if _FONT in pdfmetrics.getRegisteredFontNames():
        return
    pdfmetrics.registerFont(TTFont(_FONT, str(_FONT_DIR / "NanumGothic.ttf")))
    pdfmetrics.registerFont(TTFont(_FONT_BOLD, str(_FONT_DIR / "NanumGothicBold.ttf")))
    pdfmetrics.registerFontFamily(_FONT, normal=_FONT, bold=_FONT_BOLD)


def _styles() -> dict:
    base = dict(fontName=_FONT, textColor=INK, alignment=TA_LEFT, wordWrap="CJK")

    def style(name, **overrides):
        return ParagraphStyle(name, **{**base, **overrides})

    return {
        "title": style("title", fontName=_FONT_BOLD, fontSize=20, leading=26),
        "subtitle": style("subtitle", fontSize=9, leading=13, textColor=MUTED),
        "h2": style("h2", fontName=_FONT_BOLD, fontSize=13, leading=18, spaceBefore=14, spaceAfter=6),
        "h3": style("h3", fontName=_FONT_BOLD, fontSize=10.5, leading=15, spaceBefore=6),
        "body": style("body", fontSize=9.5, leading=15),
        "small": style("small", fontSize=8.5, leading=12.5, textColor=MUTED),
        "cell": style("cell", fontSize=8.8, leading=13),
        "cell_bold": style("cell_bold", fontName=_FONT_BOLD, fontSize=8.8, leading=13),
        "step": style("step", fontSize=8.8, leading=13, leftIndent=12, bulletIndent=4),
        "note": style("note", fontSize=8.5, leading=12.5, textColor=MUTED, leftIndent=12),
        "big": style("big", fontName=_FONT_BOLD, fontSize=28, leading=32),
    }


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _kst(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).astimezone(KST).strftime("%Y-%m-%d %H:%M (KST)")
    except ValueError:
        return iso


def _model_label(name: str) -> str:
    return "기본 템플릿" if name == "template" else escape(name)


def _table(rows, widths, header=True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), PANEL))
    table.setStyle(TableStyle(style))
    return table


def _on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont(_FONT, 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "피싱 사이트 분석기 · 이 리포트는 URL 문자열 분석 결과이며 법적 판단이 아닙니다.")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"{doc.page} 페이지")
    canvas.restoreState()


def render_report_pdf(report: ReportResponse) -> bytes:
    _register_fonts()
    s = _styles()
    width = A4[0] - 36 * mm
    story = []

    # 제목
    story += [
        _p("피싱 URL 분석 리포트", s["title"]),
        Spacer(1, 3),
        Paragraph(
            f"분석 시각 {_kst(report.analyzed_at)}   ·   리포트 작성 {_kst(report.created_at)}<br/>"
            f"리포트 작성 모델 {_model_label(report.generated_by)}   ·   "
            f"후속 조치 조사 모델 {_model_label(report.followup_by)}",
            s["subtitle"],
        ),
        Spacer(1, 10),
    ]

    level_color = LEVEL_COLORS.get(report.risk_level or "", MUTED)
    score = f"{report.risk_score:.1f}" if report.risk_score is not None else "-"
    verdict = VERDICT_KO.get(report.verdict or "", "판정 불가")
    level = LEVEL_KO.get(report.risk_level or "", "-")
    confidence = f"{round(report.confidence * 100)}%" if report.confidence is not None else "-"
    big = ParagraphStyle("big_c", parent=s["big"], textColor=level_color)
    summary_box = Table(
        [
            [
                [_p(score, big), _p("/ 100  최종 위험도", s["small"])],
                [
                    _p(f"판정: {verdict}   ·   등급: {level}   ·   신뢰도: {confidence}", s["cell_bold"]),
                    Spacer(1, 4),
                    _p(f"대상 URL: {report.url}", s["cell"]),
                ],
            ]
        ],
        colWidths=[40 * mm, width - 40 * mm],
    )
    summary_box.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1.2, level_color),
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(summary_box)

    story += [_p("1. 요약", s["h2"]), _p(report.summary, s["body"])]

    rows = [[_p("출처", s["cell_bold"]), _p("내용", s["cell_bold"]), _p("점수 반영", s["cell_bold"])]]
    for e in report.evidence:
        rows.append(
            [_p(e.source, s["cell"]), _p(e.finding, s["cell"]), _p("반영" if e.used_in_verdict else "참고", s["cell"])]
        )
    story += [
        _p("2. 판정 근거", s["h2"]),
        _table(rows, [42 * mm, width - 42 * mm - 22 * mm, 22 * mm]),
    ]

    story.append(_p("3. 유사 사례", s["h2"]))
    if report.similar_cases:
        rows = [[_p("URL", s["cell_bold"]), _p("실제 판정", s["cell_bold"]), _p("유사도", s["cell_bold"])]]
        for c in report.similar_cases:
            rows.append(
                [
                    _p(c.url, s["cell"]),
                    _p("피싱" if c.label == 1 else "정상", s["cell"]),
                    _p(f"{round(c.similarity * 100)}%", s["cell"]),
                ]
            )
        story += [
            _p("URL 특징이 가장 비슷한 과거 사례입니다. 유사도 50%는 임의의 두 URL 정도로 떨어져 있다는 뜻입니다.", s["small"]),
            Spacer(1, 4),
            _table(rows, [width - 44 * mm, 22 * mm, 22 * mm]),
        ]
    else:
        story.append(_p("유사 사례를 찾지 못했습니다.", s["body"]))

    block = [
        _p("4. AI 분석 설명", s["h2"]),
        _p(report.ai_analysis or "AI 분석 설명이 제공되지 않았습니다.", s["body"]),
    ]
    if report.ai_evidence or report.ai_guides:
        block.append(_p("설명의 출처 번호: [E]는 이 분석의 근거, [G]는 공식 기관 대응 가이드입니다.", s["small"]))
        for e in report.ai_evidence:
            block.append(Paragraph(escape(f"[{e['id']}] {e['source']}: {e['text']}"), s["step"], bulletText="·"))
        for g in report.ai_guides:
            block.append(Paragraph(escape(f"[{g['id']}] {g['title']} - {g['source']} ({g['url']})"), s["step"], bulletText="·"))
    story.append(KeepTogether(block))

    story.append(KeepTogether([_p("5. 위험 분석", s["h2"]), _p(report.risk_assessment, s["body"])]))

    heading = [
        _p("6. 후속 조치", s["h2"]),
        _p("조사 결과", s["h3"]),
        _p(report.followup_summary, s["body"]),
        Spacer(1, 6),
        _p("아래에서 본인의 상황에 해당하는 항목을 확인하세요. ★ 표시는 이 URL에 특히 중요한 조치입니다.", s["small"]),
    ]
    for i, group in enumerate(report.action_groups):
        block = (heading if i == 0 else []) + [_p(f"■ {group.situation}", s["h3"])]
        for action in group.actions:
            mark = "★ " if action.priority else ""
            block.append(_p(f"{mark}{action.title}", s["cell_bold"]))
            if action.note:
                block.append(_p(f"→ {action.note}", s["note"]))
            if action.source:
                block.append(_p(f"출처: {action.source}", s["note"]))
            for step in action.steps:
                block.append(Paragraph(escape(step), s["step"], bulletText="·"))
            block.append(Spacer(1, 4))
        story.append(KeepTogether(block))

    rows = [[_p("기관", s["cell_bold"]), _p("전화", s["cell_bold"]), _p("누리집", s["cell_bold"]), _p("용도", s["cell_bold"])]]
    for c in report.contacts:
        rows.append(
            [_p(c.name, s["cell"]), _p(c.phone or "-", s["cell"]), _p(c.url or "-", s["cell"]), _p(c.purpose, s["cell"])]
        )
    story += [
        _p("7. 신고·상담 기관", s["h2"]),
        _table(rows, [52 * mm, 14 * mm, 46 * mm, width - 112 * mm]),
    ]

    story.append(_p("8. 분석의 한계", s["h2"]))
    for item in report.limitations:
        story.append(Paragraph(escape(item), s["step"], bulletText="·"))

    story += [Spacer(1, 8), _p("참고 출처: " + " / ".join(report.references), s["small"])]

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="피싱 URL 분석 리포트",
        author="피싱 사이트 분석기",
        subject=report.url,
    )
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buffer.getvalue()
