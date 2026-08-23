"""Create a tampered PNG while preserving its C2PA chunk."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from PIL import Image


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SOURCE_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_signed.png"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_tampered.png"
)


def read_png_chunks(path: Path) -> list[tuple[bytes, bytes]]:
    """Read all PNG chunks without interpreting their contents."""
    chunks: list[tuple[bytes, bytes]] = []

    with path.open("rb") as file:
        if file.read(8) != PNG_SIGNATURE:
            raise ValueError("Invalid PNG signature.")

        while True:
            header = file.read(8)

            if len(header) != 8:
                raise ValueError("Unexpected end of PNG.")

            length, chunk_type = struct.unpack(
                ">I4s",
                header,
            )

            data = file.read(length)
            crc = file.read(4)

            if len(data) != length or len(crc) != 4:
                raise ValueError("Truncated PNG chunk.")

            chunks.append(
                (chunk_type, data)
            )

            if chunk_type == b"IEND":
                break

    return chunks


def build_png(
    chunks: list[tuple[bytes, bytes]],
) -> bytes:
    """Rebuild a PNG while preserving supplied chunk data."""
    output = bytearray(PNG_SIGNATURE)

    for chunk_type, data in chunks:
        output.extend(
            struct.pack(
                ">I",
                len(data),
            )
        )

        output.extend(chunk_type)
        output.extend(data)

        crc = zlib.crc32(
            chunk_type + data
        ) & 0xFFFFFFFF

        output.extend(
            struct.pack(
                ">I",
                crc,
            )
        )

    return bytes(output)


def main() -> None:
    if not SOURCE_PATH.is_file():
        raise FileNotFoundError(
            f"Signed asset not found: {SOURCE_PATH}"
        )

    if OUTPUT_PATH.exists():
        OUTPUT_PATH.unlink()

    chunks = read_png_chunks(
        SOURCE_PATH
    )

    original_ca_bx = [
        data
        for chunk_type, data in chunks
        if chunk_type == b"caBX"
    ]

    if not original_ca_bx:
        raise ValueError(
            "Signed PNG does not contain the expected caBX C2PA chunk."
        )

    if len(original_ca_bx) != 1:
        raise ValueError(
            "Expected exactly one caBX chunk."
        )

    image = Image.open(
        SOURCE_PATH
    ).convert("RGB")

    pixels = image.load()

    width, height = image.size

    x = width // 2
    y = height // 2

    original_pixel = pixels[x, y]

    pixels[x, y] = (
        255,
        0,
        0,
    )

    # Save only the modified image data to a temporary PNG.
    temp_image = OUTPUT_PATH.with_suffix(
        ".tmp.png"
    )

    image.save(
        temp_image,
        format="PNG",
    )

    modified_chunks = read_png_chunks(
        temp_image
    )

    temp_image.unlink()

    # The temporary PNG contains the modified image, but its own C2PA
    # metadata (if any) must not replace the original signed metadata.
    rebuilt_chunks: list[tuple[bytes, bytes]] = []

    for chunk_type, data in modified_chunks:
        if chunk_type == b"caBX":
            continue

        rebuilt_chunks.append(
            (chunk_type, data)
        )

        if chunk_type == b"IHDR":
            rebuilt_chunks.append(
                (b"caBX", original_ca_bx[0])
            )

    OUTPUT_PATH.write_bytes(
        build_png(rebuilt_chunks)
    )

    print(
        f"Created tampered asset: {OUTPUT_PATH}"
    )

    print(
        f"Modified pixel: ({x}, {y})"
    )

    print(
        f"Original pixel: {original_pixel}"
    )

    print(
        f"New pixel:      {pixels[x, y]}"
    )

    print(
        "Preserved C2PA chunk: caBX"
    )


if __name__ == "__main__":
    main()