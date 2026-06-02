#!/usr/bin/env python3
import os
import sys
from pathlib import Path


def has_file(scan_location: Path, names: set[str], suffixes: tuple[str, ...] = ()) -> bool:
    for root, _, files in os.walk(scan_location):
        for file_name in files:
            if file_name in names:
                return True
            if suffixes and file_name.endswith(suffixes):
                return True
    return False


def detect_project_type(scan_location: Path) -> str:
    if has_file(scan_location, {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}):
        return "gradle"
    if has_file(scan_location, {"pom.xml"}):
        return "maven"
    if has_file(scan_location, {"uv.lock"}):
        return "uv"
    if has_file(scan_location, {"go.mod", "go.sum"}):
        return "go"
    if has_file(scan_location, {"packages.config"}, suffixes=(".csproj", ".fsproj", ".vbproj")):
        return "dotnet"
    if has_file(scan_location, {"Gemfile", "Gemfile.lock"}):
        return "ruby"
    if has_file(scan_location, {"composer.json", "composer.lock"}):
        return "php"
    if has_file(scan_location, {"Cargo.toml", "Cargo.lock"}):
        return "rust"
    if has_file(scan_location, {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}):
        return "node"
    if has_file(scan_location, {"requirements.txt", "Pipfile", "poetry.lock", "pyproject.toml"}):
        return "python"
    return "unknown"


def main() -> int:
    scan_location = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")

    if not scan_location.is_dir():
        print(f"Filesystem scan location does not exist: '{scan_location}'", file=sys.stderr)
        return 1

    print(f"project_type={detect_project_type(scan_location)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
