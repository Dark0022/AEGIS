"""Inspect PNG chunk types in an AEGIS asset."""

from __future__ import annotations

import struct
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PNG_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_signed.png"
)


def main() -> None:
    if not PNG_PATH.is_file():
        raise FileNotFoundError(
            f"PNG not found: {PNG_PATH}"
        )

    with PNG_PATH.open("rb") as file:
        signature = file.read(8)

        if signature != b"\x89PNG\r\n\x1a\n":
            raise ValueError("Not a valid PNG file.")

        index = 0

        while True:
            header = file.read(8)

            if len(header) != 8:
                break

            length, chunk_type = struct.unpack(
                ">I4s",
                header,
            )

            chunk_name = chunk_type.decode(
                "latin1"
            )

            print(
                f"{index:02d}: "
                f"{chunk_name} "
                f"({length} bytes)"
            )

            file.seek(
                length + 4,
                1,
            )

            index += 1

            if chunk_type == b"IEND":
                break


if __name__ == "__main__":
    main()