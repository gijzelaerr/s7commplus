"""The preset dictionaries load through importlib.resources, not from a directory on disk."""

import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import s7commplus
from s7commplus.zlib_dicts import ZLIB_DICTIONARIES

_PACKAGE = Path(s7commplus.__file__).parent


def test_every_dictionary_is_keyed_by_its_adler32() -> None:
    assert len(ZLIB_DICTIONARIES) == len(list((_PACKAGE / "zlib_dicts").glob("*.xml")))
    for adler, dictionary in ZLIB_DICTIONARIES.items():
        assert zlib.adler32(dictionary) == adler


def test_dictionaries_load_from_a_zipped_package(tmp_path: Path) -> None:
    archive = tmp_path / "s7commplus.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        for path in sorted(_PACKAGE.rglob("*")):
            if path.suffix in (".py", ".xml"):
                zipped.write(path, Path("s7commplus") / path.relative_to(_PACKAGE))
    script = (
        "import sys; sys.path.insert(0, sys.argv[1]); import s7commplus.zlib_dicts as z; "
        "assert z.__file__.startswith(sys.argv[1]), z.__file__; print(len(z.ZLIB_DICTIONARIES))"
    )

    result = subprocess.run([sys.executable, "-I", "-c", script, str(archive)], capture_output=True, text=True, cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert int(result.stdout) == len(ZLIB_DICTIONARIES)
