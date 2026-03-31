import json
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm


def build_pdf_report(input_type: str, input_value: str, result: dict) -> bytes:
    """
    Returns a PDF as bytes.
    """
    from io import BytesIO
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    y = height - 2 * cm

    def line(txt, dy=14):
        nonlocal y
        c.drawString(2 * cm, y, txt[:120])
        y -= dy
        if y < 2 * cm:
            c.showPage()
            y = height - 2 * cm

    c.setFont("Helvetica-Bold", 16)
    line("DarkHorse AI — Threat Analysis Report", dy=20)

    c.setFont("Helvetica", 10)
    line(f"Generated: {datetime.utcnow().isoformat()} UTC", dy=16)
    line(f"Input Type: {input_type}", dy=16)

    c.setFont("Helvetica-Bold", 12)
    line("Input:", dy=18)
    c.setFont("Helvetica", 10)
    for chunk in _wrap(input_value, 110):
        line(chunk)

    c.setFont("Helvetica-Bold", 12)
    line("Result Summary:", dy=18)
    c.setFont("Helvetica", 10)
    line(f"Label: {result.get('label')}")
    line(f"Risk Score: {result.get('score')}/100")
    line(f"Confidence: {result.get('confidence')}%")

    c.setFont("Helvetica-Bold", 12)
    line("Reasons:", dy=18)
    c.setFont("Helvetica", 10)
    for r in result.get("reasons", []):
        for chunk in _wrap(f"- {r}", 110):
            line(chunk)

    c.setFont("Helvetica-Bold", 12)
    line("Detected Categories:", dy=18)
    c.setFont("Helvetica", 9)
    cats = result.get("detected_categories", {})
    line(json.dumps(cats, ensure_ascii=False)[:400])

    c.showPage()
    c.save()

    return buf.getvalue()


def _wrap(text: str, max_len: int):
    words = text.split()
    out, cur = [], []
    for w in words:
        if sum(len(x) for x in cur) + len(cur) + len(w) > max_len:
            out.append(" ".join(cur))
            cur = [w]
        else:
            cur.append(w)
    if cur:
        out.append(" ".join(cur))
    return out