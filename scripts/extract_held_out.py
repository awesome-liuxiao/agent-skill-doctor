from __future__ import annotations

import argparse
import base64
import binascii
import os
import tarfile
from pathlib import Path, PurePosixPath


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--base64-env")
    arguments = parser.parse_args()
    if arguments.base64_env is not None:
        encoded = os.environ.get(arguments.base64_env)
        if not encoded:
            raise SystemExit("held-out archive secret is missing")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise SystemExit("held-out archive secret is not valid base64") from error
        if len(decoded) > 100 * 1024 * 1024:
            raise SystemExit("held-out archive exceeds the 100 MB limit")
        arguments.archive.write_bytes(decoded)
    destination = arguments.destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(arguments.archive, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 10_000:
            raise SystemExit("held-out archive exceeds the entry limit")
        total = 0
        for member in members:
            path = PurePosixPath(member.name.replace("\\", "/"))
            total += member.size
            if (
                path.is_absolute()
                or ".." in path.parts
                or (path.parts and path.parts[0].endswith(":"))
                or member.issym()
                or member.islnk()
                or member.isdev()
                or not (member.isfile() or member.isdir())
            ):
                raise SystemExit("held-out archive contains an unsafe entry")
        if total > 100 * 1024 * 1024:
            raise SystemExit("held-out archive exceeds the 100 MB limit")
        for member in members:
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination):
                raise SystemExit("held-out archive escaped its destination")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise SystemExit("held-out archive entry cannot be read")
            with target.open("xb") as output:
                output.write(stream.read())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
