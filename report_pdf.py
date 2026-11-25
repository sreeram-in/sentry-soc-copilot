"""Builds the downloadable PDF session report (fpdf2) -- Terminal.css styled:
cream paper background, black monospace text, pipe-fill headers, flat boxes."""
from datetime import datetime
from typing import Optional

from fpdf import FPDF

PAPER = (240, 237, 227)   # cream background
INK = (25, 24, 22)        # near-black text
ORANGE = (232, 89, 12)    # accent, matches the site
DIM = (120, 115, 100)     # secondary text / empty bar
WHITE = (250, 248, 243)


def _s(text):
    """Courier only supports latin-1, so replace anything else."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def _trunc(text, max_chars):
    text = _s(text)
    return text if len(text) <= max_chars else text[: max_chars - 1] + "~"


class _ReportPDF(FPDF):
    def header(self):
        self.set_fill_color(*PAPER)
        self.rect(0, 0, 210, 297, "F")

        self.set_xy(12, 12)
        self.set_font("Courier", "B", 15)
        self.set_text_color(*INK)
        label = "SENTRY -- SOC SESSION REPORT "
        self.cell(self.get_string_width(label), 8, label)
        pipe_w = self.get_string_width("|")
        remaining = 186 - self.get_string_width(label)
        n = max(int(remaining / pipe_w), 0)
        self.set_text_color(*ORANGE)
        self.cell(remaining, 8, "|" * n)
        self.ln(9)

        self.set_x(12)
        self.set_font("Courier", "", 8.5)
        self.set_text_color(*DIM)
        self.cell(0, 5, f"generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                  new_x="LMARGIN", new_y="NEXT")

        self.set_draw_color(*INK)
        self.set_line_width(0.5)
        self.line(12, 24, 198, 24)
        self.set_y(30)
        self.set_text_color(*INK)

    def footer(self):
        self.set_y(-15)
        self.set_font("Courier", "", 8)
        self.set_text_color(*DIM)
        self.cell(0, 10, f"-- page {self.page_no()} --", align="C")

    def section_title(self, text):
        self.ln(3)
        self.set_font("Courier", "B", 11)
        self.set_text_color(*INK)
        self.cell(0, 7, _s(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*INK)
        self.set_line_width(0.3)
        self.line(self.get_x(), self.get_y(), 198, self.get_y())
        self.ln(3)
        self.set_font("Courier", "", 9.5)
        self.set_text_color(*INK)

    def stat_row(self, items):
        """Flat bordered boxes, alternating paper/black/orange -- like a Terminal.css button row."""
        fills = [None, INK, ORANGE]
        text_colors = [INK, WHITE, INK]
        n = len(items)
        w = 190 / n
        x0, y0 = self.get_x(), self.get_y()
        for i, (val, label) in enumerate(items):
            x = x0 + i * w
            fill = fills[i % len(fills)]
            tcol = text_colors[i % len(text_colors)]
            self.set_draw_color(*INK)
            self.set_line_width(0.5)
            if fill:
                self.set_fill_color(*fill)
                self.rect(x, y0, w - 4, 20, "DF")
            else:
                self.rect(x, y0, w - 4, 20)
            self.set_xy(x, y0 + 3)
            self.set_font("Courier", "B", 15)
            self.set_text_color(*tcol)
            self.cell(w - 4, 8, _s(val), align="C")
            self.set_xy(x, y0 + 12)
            self.set_font("Courier", "", 7.5)
            self.cell(w - 4, 5, _s(label), align="C")
        self.set_xy(x0, y0 + 24)
        self.set_text_color(*INK)

    def category_bars(self, by_label):
        if not by_label:
            self._empty_note()
            return
        max_count = max(by_label.values())
        self.set_font("Courier", "", 9)
        char_w = self.get_string_width("#")
        bar_chars = 28
        for label, count in sorted(by_label.items(), key=lambda kv: -kv[1]):
            self.set_text_color(*INK)
            self.cell(38, 6, _trunc(label, 20))
            filled_n = max(int(bar_chars * (count / max_count)), 1) if max_count else 0
            filled_n = min(filled_n, bar_chars)
            empty_n = bar_chars - filled_n

            self.cell(char_w, 6, "[")
            self.set_text_color(*ORANGE)
            self.cell(char_w * filled_n, 6, "#" * filled_n)
            self.set_text_color(*DIM)
            self.cell(char_w * empty_n, 6, "." * empty_n)
            self.set_text_color(*INK)
            self.cell(char_w, 6, "]")
            self.cell(10, 6, " " + str(count))
            self.ln(6)
        self.set_text_color(*INK)

    def alerts_table(self, alerts):
        if not alerts:
            self._empty_note()
            return
        headers = ["TIME", "SOURCE", "DEST", "PROTO", "LABEL", "CONF"]
        widths = [20, 45, 45, 16, 40, 24]
        self._table_header(headers, widths)
        self.set_font("Courier", "", 8)
        for i, a in enumerate(alerts[:60]):
            if self.get_y() > 265:
                self.add_page()
                self._table_header(headers, widths)
                self.set_font("Courier", "", 8)
            self.set_text_color(*(ORANGE if a["is_attack"] else INK))
            row = [a["time"], a["src"], a["dst"], a["protocol"],
                   a["label"] if a["is_attack"] else "Anomaly", f"{a['confidence']}%"]
            for val, w in zip(row, widths):
                self.cell(w, 6, _trunc(val, int(w * 0.5)))
            self.ln()
        self.set_text_color(*INK)
        if len(alerts) > 60:
            self.set_font("Courier", "I", 8)
            self.set_text_color(*DIM)
            self.cell(0, 6, f"...and {len(alerts) - 60} more (see the live dashboard for the full list).",
                      new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(*INK)

    def risk_table(self, leaderboard):
        if not leaderboard:
            self._empty_note()
            return
        self._table_header(["SOURCE IP", "RISK", "ATTACK / ANOMALY TYPES"], [55, 25, 110])
        self.set_font("Courier", "", 9)
        for row in leaderboard:
            if self.get_y() > 265:
                self.add_page()
                self._table_header(["SOURCE IP", "RISK", "ATTACK / ANOMALY TYPES"], [55, 25, 110])
                self.set_font("Courier", "", 9)
            types = ", ".join(f"{k} x{v}" for k, v in row["by_label"].items())
            self.set_text_color(*INK)
            self.cell(55, 6, _trunc(row["ip"], 26))
            self.set_text_color(*(ORANGE if row["risk_score"] >= 3 else INK))
            self.cell(25, 6, str(row["risk_score"]))
            self.set_text_color(*INK)
            self.cell(110, 6, _trunc(types, 62))
            self.ln()
        self.set_text_color(*INK)

    def _table_header(self, headers, widths):
        self.set_font("Courier", "B", 8.5)
        self.set_fill_color(*INK)
        self.set_text_color(*WHITE)
        for h, w in zip(headers, widths):
            self.cell(w, 7, h, fill=True)
        self.ln()
        self.set_text_color(*INK)

    def _empty_note(self):
        self.set_font("Courier", "I", 9.5)
        self.set_text_color(*DIM)
        self.cell(0, 6, "-- no flagged flows this session --", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*INK)


def build_report_pdf(stats: dict, narrative: Optional[str], leaderboard: list,
                     alerts: Optional[list] = None) -> bytes:
    alerts = alerts or []
    pdf = _ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    flag_rate = round(100 * stats["total_flagged"] / stats["total_flows"], 1) if stats["total_flows"] else 0
    pdf.stat_row([
        (stats["total_flows"], "FLOWS ANALYZED"),
        (stats["total_flagged"], "FLAGGED"),
        (f"{flag_rate}%", "FLAG RATE"),
    ])

    if narrative:
        pdf.section_title("AI Summary")
        pdf.set_font("Courier", "", 9.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5.5, _s(narrative), new_x="LMARGIN", new_y="NEXT")

    pdf.section_title("Breakdown by Category")
    pdf.category_bars(stats["by_label"])

    pdf.section_title("Per-Source Risk Leaderboard")
    pdf.risk_table(leaderboard)

    pdf.section_title("Flagged Flows -- Detail")
    pdf.alerts_table(alerts)

    return bytes(pdf.output())