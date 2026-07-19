from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--name", required=True)
    arguments = parser.parse_args()
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None or not epoch.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH is required for a release build")
    arguments.output.mkdir(parents=True, exist_ok=True)
    work_root = Path("build") / arguments.name
    work_root.mkdir(parents=True, exist_ok=True)
    build_environment = {
        name: os.environ[name]
        for name in (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "HOME",
            "TMP",
            "TEMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
        )
        if name in os.environ
    }
    build_environment.update(
        {
            "PYTHONHASHSEED": "0",
            "PYINSTALLER_CONFIG_DIR": str((work_root / "config").resolve()),
            "SOURCE_DATE_EPOCH": epoch,
        }
    )
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            arguments.name,
            "--specpath",
            str(work_root),
            "--workpath",
            str(work_root / "work"),
            "--distpath",
            str(arguments.output),
            "--collect-data",
            "skill_doctor",
            "src/skill_doctor/__main__.py",
        ],
        check=True,
        env=build_environment,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
