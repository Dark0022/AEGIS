"""Create a synthetic AEGIS institutional notice for development testing."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


PROJECT_ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice.pdf"
)


def main() -> None:
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    pdf = canvas.Canvas(
        str(OUTPUT_PATH),
        pagesize=A4,
    )

    width, height = A4

    pdf.setTitle(
        "AEGIS Development Emergency Notice"
    )

    pdf.setFont(
        "Helvetica-Bold",
        18,
    )

    pdf.drawString(
        72,
        height - 90,
        "SOA UNIVERSITY",
    )

    pdf.setFont(
        "Helvetica-Bold",
        14,
    )

    pdf.drawString(
        72,
        height - 125,
        "Emergency Management Office",
    )

    pdf.setFont(
        "Helvetica",
        11,
    )

    pdf.drawString(
        72,
        height - 170,
        "OFFICIAL EMERGENCY NOTICE",
    )

    pdf.setFont(
        "Helvetica",
        12,
    )

    pdf.drawString(
        72,
        height - 215,
        "Development Test Notice",
    )

    pdf.setFont(
        "Helvetica",
        10,
    )

    body = [
        "This document is a synthetic development asset",
        "used exclusively to test the AEGIS provenance",
        "and verification pipeline.",
        "",
        "AEGIS must be able to establish whether this",
        "exact document was issued by an authorized",
        "institutional signing identity.",
    ]

    y = height - 260

    for line in body:
        pdf.drawString(
            72,
            y,
            line,
        )
        y -= 18

    pdf.setFont(
        "Helvetica-Oblique",
        9,
    )

    pdf.drawString(
        72,
        72,
        "AEGIS development asset — not an actual university notice.",
    )

    pdf.save()

    print(
        f"Created: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()