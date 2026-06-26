from __future__ import annotations

import zipfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
OUTPUT_ZIP = ROOT_DIR.parent / "KubeSentinel_Streamlit_App.zip"

EXCLUDED_DIRS = {
    ".venv",
    "__pycache__",
    ".streamlit",
    "logs",
    "uploads",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
}


def should_include(path: Path) -> bool:
    rel_parts = set(path.relative_to(ROOT_DIR).parts)
    if rel_parts.intersection(EXCLUDED_DIRS):
        return False
    if path.suffix in EXCLUDED_SUFFIXES:
        return False
    if path.name == OUTPUT_ZIP.name:
        return False
    return True


def main() -> None:
    with zipfile.ZipFile(OUTPUT_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(ROOT_DIR.rglob("*")):
            if path.is_file() and should_include(path):
                archive.write(path, path.relative_to(ROOT_DIR.parent))
    print(f"Created {OUTPUT_ZIP}")


if __name__ == "__main__":
    main()
