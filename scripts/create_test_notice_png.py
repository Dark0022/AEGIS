"""Create a synthetic AEGIS PNG notice for C2PA testing."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


PROJECT_ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice.png"
)


def main() -> None:
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    width = 1600
    height = 1000

    image = Image.new(
        "RGB",
        (width, height),
        "white",
    )

    draw = ImageDraw.Draw(image)

    title_font = ImageFont.truetype(
        "arialbd.ttf",
        56,
    )

    subtitle_font = ImageFont.truetype(
        "arialbd.ttf",
        36,
    )

    body_font = ImageFont.truetype(
        "arial.ttf",
        28,
    )

    draw.text(
        (120, 100),
        "SOA UNIVERSITY",
        fill="black",
        font=title_font,
    )

    draw.text(
        (120, 180),
        "Emergency Management Office",
        fill="black",
        font=subtitle_font,
    )

    draw.line(
        (120, 245, 1480, 245),
        fill="black",
        width=3,
    )

    draw.text(
        (120, 310),
        "OFFICIAL DEVELOPMENT NOTICE",
        fill="black",
        font=subtitle_font,
    )

    lines = [
        "This is a synthetic AEGIS test asset.",
        "",
        "It is used to verify cryptographic provenance,",
        "content integrity, and institutional signing.",
        "",
        "This image is NOT an actual university notice.",
    ]

    y = 390

    for line in lines:
        draw.text(
            (120, y),
            line,
            fill="black",
            font=body_font,
        )
        y += 55

    draw.text(
        (120, 850),
        "AEGIS development asset",
        fill="black",
        font=body_font,
    )

    image.save(
        OUTPUT_PATH,
        format="PNG",
    )

    print(
        f"Created: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()