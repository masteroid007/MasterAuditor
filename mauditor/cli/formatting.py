from pathlib import Path
from urllib.parse import quote


def hyperlink(text: str, file_path: Path, line: int) -> str:
    path = file_path.resolve().as_posix()
    url = f"file:///{quote(path)}"

    return f"'\033]8;;{url}\033\\{text}\033]8;;\033\\'"