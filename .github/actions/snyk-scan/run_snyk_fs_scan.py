#!/usr/bin/env python3
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


MANIFEST_PATTERNS = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "requirements.txt",
    "Pipfile",
    "poetry.lock",
    "pyproject.toml",
    "uv.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "composer.json",
    "composer.lock",
    "Cargo.toml",
    "Cargo.lock",
    "packages.config",
}


def eprint(msg: str) -> None:
    print(msg)


def has_supported_manifest(scan_location: Path) -> bool:
    for root, _, files in os.walk(scan_location):
        for name in files:
            if name in MANIFEST_PATTERNS:
                return True
            if name.endswith((".csproj", ".fsproj", ".vbproj")):
                return True
    return False


def find_first(scan_location: Path, names: tuple[str, ...]) -> Path | None:
    for root, _, files in os.walk(scan_location):
        for name in files:
            if name in names:
                return Path(root) / name
    return None


def run_capture(args: list[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=check,
    )


def maybe_gradle_preflight(scan_location: Path) -> bool:
    gradle_manifest = find_first(scan_location, ("build.gradle", "build.gradle.kts"))
    if not gradle_manifest:
        return True

    gradle_dir = gradle_manifest.parent
    gradlew_cmd: Path | None = None
    local_gradlew = gradle_dir / "gradlew"
    root_gradlew = scan_location / "gradlew"

    if local_gradlew.exists() and os.access(local_gradlew, os.X_OK):
        gradlew_cmd = local_gradlew
    elif root_gradlew.exists() and os.access(root_gradlew, os.X_OK):
        gradlew_cmd = root_gradlew

    if gradlew_cmd is None:
        eprint("Gradle manifest detected but no executable gradlew found. Adding a Gradle wrapper is recommended for reliable CI dependency resolution.")
        return False

    eprint(f"Running Gradle preflight in '{gradle_dir}' via '{gradlew_cmd}'")
    gradle_version_output = run_capture([str(gradlew_cmd), "-v"]).stdout
    gradle_major_match = re.search(r"^Gradle\s+([0-9]+)\.", gradle_version_output, flags=re.MULTILINE)
    gradle_major = int(gradle_major_match.group(1)) if gradle_major_match else None

    snyk_version_output = run_capture(["snyk", "--version"]).stdout.strip()
    snyk_parts = snyk_version_output.split(".")
    snyk_major = int(snyk_parts[0]) if len(snyk_parts) > 1 and snyk_parts[0].isdigit() else None
    snyk_minor = int(snyk_parts[1]) if len(snyk_parts) > 1 and snyk_parts[1].isdigit() else None

    if gradle_major is not None and gradle_major >= 9 and snyk_major == 1 and snyk_minor is not None and snyk_minor < 1300:
        eprint(f"Detected Gradle {gradle_major}.x with Snyk CLI {snyk_version_output}.")
        eprint("This combination can fail with '--build-file' errors.")
        eprint("Update the centrally managed Snyk CLI version in this action or pin Gradle wrapper to 8.x for scanning.")

    with open("gradle-preflight.log", "w", encoding="utf-8") as f:
        proc = subprocess.run(
            [str(gradlew_cmd), "-q", "help", "--no-daemon", "--stacktrace"],
            cwd=str(gradle_dir),
            text=True,
            stdout=f,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if proc.returncode != 0:
        eprint("Gradle preflight failed before Snyk scan. This usually indicates dependency repository auth or build configuration issues.")
        eprint("Last 200 lines of gradle-preflight.log:")
        try:
            with open("gradle-preflight.log", "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[-200:]:
                print(line.rstrip("\n"))
        except FileNotFoundError:
            pass
        raise SystemExit(2)

    return False


def run_snyk_test(scan_location: Path, severity_threshold: str, policy_path: Path | None, use_all_projects: bool, debug: bool = False) -> int:
    cmd = ["snyk", "test", str(scan_location), f"--severity-threshold={severity_threshold}"]
    if use_all_projects:
        cmd.insert(3, "--all-projects")
    if policy_path and policy_path.exists():
        cmd.append(f"--policy-path={policy_path}")
    if debug:
        cmd.append("-d")
    if not debug:
        cmd.append("--sarif-file-output=snyk-results.sarif")

    env = os.environ.copy()
    if debug:
        env["DEBUG"] = "*snyk*"

    if debug:
        with open("snyk-debug.log", "w", encoding="utf-8") as f:
            proc = subprocess.run(cmd, text=True, stdout=f, stderr=subprocess.STDOUT, env=env, check=False)
            return proc.returncode

    proc = subprocess.run(cmd, text=True, env=env, check=False)
    return proc.returncode


def print_debug_log_snippet() -> None:
    try:
        with open("snyk-debug.log", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return

    start_marker = "===== DEBUG INFORMATION START ====="
    end_marker = "===== DEBUG INFORMATION END ====="
    if start_marker in content and end_marker in content:
        eprint("Snyk debug information block:")
        start = content.find(start_marker)
        end = content.find(end_marker, start)
        if end != -1:
            block = content[start:end + len(end_marker)]
            lines = block.splitlines()[-400:]
            for line in lines:
                print(line)
            return

    eprint("Last 200 lines of Snyk debug log:")
    for line in content.splitlines()[-200:]:
        print(line)


def main() -> int:
    scan_location = Path(os.getenv("SCAN_LOCATION", "."))
    severity_threshold = os.getenv("SEVERITY_THRESHOLD", "high")
    policy_path_input = os.getenv("SNYK_POLICY_PATH_INPUT", "")

    if not scan_location.is_dir():
        eprint(f"Snyk filesystem scan location does not exist or is not a directory: '{scan_location}'")
        return 1

    if not has_supported_manifest(scan_location):
        eprint(f"Snyk filesystem scan could not find supported target files in '{scan_location}'.")
        eprint("Set 'location' to a directory containing manifests like package.json, pom.xml, build.gradle, requirements.txt, pyproject.toml, or go.mod.")
        return 1

    use_all_projects = maybe_gradle_preflight(scan_location)

    eprint("Java runtime for fs scan:")
    java_bin = shutil.which("java")
    if java_bin:
        subprocess.run([java_bin, "-version"], check=False)

    policy_path = Path(policy_path_input) if policy_path_input else (scan_location / ".snyk")
    if policy_path.exists():
        eprint(f"Applying Snyk policy file: {policy_path}")

    if not use_all_projects:
        eprint("Gradle project detected; running Snyk without --all-projects to avoid Gradle 9 compatibility issue.")

    cmd_exit = run_snyk_test(scan_location, severity_threshold, policy_path, use_all_projects, debug=False)

    if cmd_exit == 3:
        eprint(f"Snyk filesystem scan could not find supported target files in '{scan_location}'.")
        eprint("Set 'location' to a directory containing supported manifests (for example pom.xml, build.gradle, package.json, requirements.txt).")
        return cmd_exit

    if cmd_exit == 2:
        eprint("Snyk filesystem scan failed to resolve dependencies (exit code 2).")
        eprint("Common causes: private package repo credentials missing, Gradle/Maven auth config missing, missing ecosystem tools in runner, or project toolchain mismatch.")
        eprint("Re-running Snyk in debug mode to surface root cause...")
        _ = run_snyk_test(scan_location, severity_threshold, policy_path, use_all_projects, debug=True)
        print_debug_log_snippet()
        return cmd_exit

    if cmd_exit > 1:
        eprint(f"Snyk filesystem scan failed with exit code {cmd_exit}")
        return cmd_exit

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
