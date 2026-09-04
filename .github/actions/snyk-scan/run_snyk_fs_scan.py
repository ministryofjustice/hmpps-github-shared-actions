#!/usr/bin/env python3
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


SUPPORTED_EXACT_FILES = {
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
SUPPORTED_SUFFIXES = (".csproj", ".fsproj", ".vbproj")


def emit_summary_message(message: str) -> None:
  github_output = os.environ.get("GITHUB_OUTPUT", "")
  if github_output:
    with open(github_output, "a", encoding="utf-8") as output:
      output.write(f"summary_message={message}\n")


def run_command(
  args: Sequence[str],
  *,
  cwd: Optional[str] = None,
  env: Optional[dict] = None,
  capture: bool = False,
  check: bool = False,
) -> subprocess.CompletedProcess:
  if capture:
    return subprocess.run(
      args,
      cwd=cwd,
      env=env,
      text=True,
      capture_output=True,
      check=check,
    )
  return subprocess.run(args, cwd=cwd, env=env, check=check)


def has_supported_manifest(scan_location: Path) -> bool:
  for root, _, files in os.walk(scan_location):
    for file_name in files:
      if file_name in SUPPORTED_EXACT_FILES:
        return True
      if file_name.endswith(SUPPORTED_SUFFIXES):
        return True
  return False


def find_first_gradle_manifest(scan_location: Path) -> Optional[Path]:
  for root, _, files in os.walk(scan_location):
    if "build.gradle" in files:
      return Path(root) / "build.gradle"
    if "build.gradle.kts" in files:
      return Path(root) / "build.gradle.kts"
  return None


def parse_gradle_major(gradle_version_output: str) -> Optional[int]:
  match = re.search(r"^Gradle\s+(\d+)\.", gradle_version_output, flags=re.MULTILINE)
  if not match:
    return None
  return int(match.group(1))


def parse_snyk_major_minor(
  snyk_version_output: str,
) -> Tuple[Optional[int], Optional[int]]:
  match = re.search(r"(\d+)\.(\d+)", snyk_version_output)
  if not match:
    return None, None
  return int(match.group(1)), int(match.group(2))


def print_tail(path: Path, line_count: int) -> None:
  if not path.exists():
    return
  with open(path, "r", encoding="utf-8", errors="replace") as file_handle:
    lines = file_handle.readlines()
  for line in lines[-line_count:]:
    print(line.rstrip("\n"))


def print_debug_block_or_tail(path: Path) -> None:
  if not path.exists():
    return

  with open(path, "r", encoding="utf-8", errors="replace") as file_handle:
    lines = file_handle.readlines()

  start_idx = None
  end_idx = None
  for idx, line in enumerate(lines):
    if "===== DEBUG INFORMATION START =====" in line and start_idx is None:
      start_idx = idx
    if "===== DEBUG INFORMATION END =====" in line:
      end_idx = idx

  if start_idx is not None and end_idx is not None and end_idx >= start_idx:
    print("Snyk debug information block:")
    block = lines[start_idx : end_idx + 1]
    for line in block[-400:]:
      print(line.rstrip("\n"))
    return

  print("Last 200 lines of Snyk debug log:")
  for line in lines[-200:]:
    print(line.rstrip("\n"))


def main() -> int:
  env = dict(os.environ)

  snyk_token = env.get("SNYK_TOKEN", "")
  if snyk_token:
    env["SNYK_TOKEN"] = snyk_token.replace("\r", "").replace("\n", "")
  else:
    env.pop("SNYK_TOKEN", None)

  scan_location = Path(env.get("SCAN_LOCATION", "."))
  severity_threshold = env.get("SEVERITY_THRESHOLD", "high")
  policy_path_input = env.get("SNYK_POLICY_PATH_INPUT", "")

  if not scan_location.is_dir():
    message = f"Snyk filesystem scan location does not exist or is not a directory: '{scan_location}'"
    emit_summary_message(message)
    print(message)
    return 1

  if not has_supported_manifest(scan_location):
    message = f"Snyk filesystem scan could not find supported target files in '{scan_location}'."
    emit_summary_message(message)
    print(message)
    print(
      "Set 'location' to a directory containing manifests like package.json, pom.xml, build.gradle, "
      "requirements.txt, pyproject.toml, or go.mod."
    )
    return 1

  gradle_manifest = find_first_gradle_manifest(scan_location)
  use_all_projects = True
  if gradle_manifest is not None:
    use_all_projects = False
    gradle_dir = gradle_manifest.parent
    gradlew_cmd: Optional[Path] = None

    gradle_dir_gradlew = gradle_dir / "gradlew"
    scan_location_gradlew = scan_location / "gradlew"
    if gradle_dir_gradlew.exists() and os.access(gradle_dir_gradlew, os.X_OK):
      gradlew_cmd = gradle_dir_gradlew
    elif scan_location_gradlew.exists() and os.access(
      scan_location_gradlew, os.X_OK
    ):
      gradlew_cmd = scan_location_gradlew

    if gradlew_cmd is not None:
      print(f"Running Gradle preflight in '{gradle_dir}' via '{gradlew_cmd}'")

      gradle_version_proc = run_command(
        [str(gradlew_cmd), "-v"], capture=True, env=env
      )
      gradle_version_output = (gradle_version_proc.stdout or "") + (
        gradle_version_proc.stderr or ""
      )
      gradle_major = parse_gradle_major(gradle_version_output)

      snyk_version_proc = run_command(
        ["snyk", "--version"], capture=True, env=env
      )
      snyk_version_output = (snyk_version_proc.stdout or "") + (
        snyk_version_proc.stderr or ""
      )
      snyk_major, snyk_minor = parse_snyk_major_minor(snyk_version_output)

      if (
        gradle_major is not None
        and gradle_major >= 9
        and snyk_major is not None
        and snyk_minor is not None
        and snyk_major == 1
        and snyk_minor < 1300
      ):
        print(
          f"Detected Gradle {gradle_major}.x with Snyk CLI {snyk_version_output.strip()}."
        )
        print("This combination can fail with '--build-file' errors.")
        print(
          "Update the centrally managed Snyk CLI version in this action or pin Gradle wrapper to 8.x for scanning."
        )

      gradle_log = Path("gradle-preflight.log")
      with open(gradle_log, "w", encoding="utf-8") as log_handle:
        proc = subprocess.run(
          [str(gradlew_cmd), "-q", "help", "--no-daemon", "--stacktrace"],
          cwd=str(gradle_dir),
          env=env,
          stdout=log_handle,
          stderr=subprocess.STDOUT,
          text=True,
        )

      if proc.returncode != 0:
        print(
          "Gradle preflight failed before Snyk scan. This usually indicates dependency repository auth or build configuration issues."
        )
        print("Last 200 lines of gradle-preflight.log:")
        print_tail(gradle_log, 200)
        return 2
    else:
      print(
        "Gradle manifest detected but no executable gradlew found. Adding a Gradle wrapper is recommended for reliable CI dependency resolution."
      )

  print("Java runtime for fs scan:")
  run_command(["java", "-version"], env=env)

  policy_path = (
    Path(policy_path_input) if policy_path_input else scan_location / ".snyk"
  )
  policy_arg: List[str] = []
  if policy_path.is_file():
    policy_arg = [f"--policy-path={policy_path}"]
    print(f"Applying Snyk policy file: {policy_path}")

  if (scan_location / "pyproject.toml").is_file() and (
    scan_location / "uv.lock"
  ).is_file():
    print("Ensuring uv dependencies are in sync...")
    if shutil.which("uv"):
      run_command(["uv", "lock"], cwd=str(scan_location), env=env)
      run_command(["uv", "sync"], cwd=str(scan_location), env=env)
    else:
      print("uv not found, skipping uv sync step")

  base_args = [
    "snyk",
    "test",
    str(scan_location),
    f"--severity-threshold={severity_threshold}",
    *policy_arg,
    "--json-file-output=snyk-results.json",
    "--sarif-file-output=snyk-results.sarif",
  ]

  if use_all_projects:
    snyk_args = [
      "snyk",
      "test",
      str(scan_location),
      "--all-projects",
      *base_args[3:],
    ]
  else:
    print(
      "Gradle project detected; running Snyk without --all-projects to avoid Gradle 9 compatibility issue."
    )
    snyk_args = base_args

  cmd_exit = run_command(snyk_args, env=env).returncode

  if cmd_exit == 3:
    message = f"Snyk filesystem scan could not find supported target files in '{scan_location}'."
    emit_summary_message(message)
    print(message)
    print(
      "Set 'location' to a directory containing supported manifests (for example pom.xml, build.gradle, package.json, requirements.txt)."
    )
    return cmd_exit

  if cmd_exit == 2:
    print("Snyk filesystem scan failed to resolve dependencies (exit code 2).")
    print(
      "Common causes: private package repo credentials missing, Gradle/Maven auth config missing, missing ecosystem tools in runner, or project toolchain mismatch."
    )
    print("Re-running Snyk in debug mode to surface root cause...")

    debug_log = Path("snyk-debug.log")
    debug_env = dict(env)
    debug_env["DEBUG"] = "*snyk*"

    debug_base_args = [
      "snyk",
      "test",
      str(scan_location),
      f"--severity-threshold={severity_threshold}",
      *policy_arg,
      "-d",
    ]
    if use_all_projects:
      debug_args = [
        "snyk",
        "test",
        str(scan_location),
        "--all-projects",
        *debug_base_args[3:],
      ]
    else:
      debug_args = debug_base_args

    with open(debug_log, "w", encoding="utf-8") as log_handle:
      subprocess.run(
        debug_args,
        env=debug_env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
      )

    print_debug_block_or_tail(debug_log)
    return cmd_exit

  if cmd_exit > 1:
    print(f"Snyk filesystem scan failed with exit code {cmd_exit}")
    return cmd_exit

  return 0


if __name__ == "__main__":
  sys.exit(main())
