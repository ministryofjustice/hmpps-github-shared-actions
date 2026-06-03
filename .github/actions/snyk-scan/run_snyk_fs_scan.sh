#!/usr/bin/env bash
set -euo pipefail

# set token when provided, otherwise leave OAuth/session auth intact.
if [[ -n "${SNYK_TOKEN:-}" ]]; then
  export SNYK_TOKEN="$(printf '%s' "$SNYK_TOKEN" | tr -d '\r\n')"
else
  unset SNYK_TOKEN || true
fi

scan_location="${SCAN_LOCATION:-.}"
severity_threshold="${SEVERITY_THRESHOLD:-high}"
policy_path_input="${SNYK_POLICY_PATH_INPUT:-}"

if [[ ! -d "$scan_location" ]]; then
  echo "Snyk filesystem scan location does not exist or is not a directory: '$scan_location'"
  exit 1
fi

# Fail early with a clear message when the target directory has no supported manifests.
if ! find "$scan_location" -type f \( \
  -name 'package.json' -o \
  -name 'package-lock.json' -o \
  -name 'yarn.lock' -o \
  -name 'pnpm-lock.yaml' -o \
  -name 'pom.xml' -o \
  -name 'build.gradle' -o \
  -name 'build.gradle.kts' -o \
  -name 'settings.gradle' -o \
  -name 'settings.gradle.kts' -o \
  -name 'requirements.txt' -o \
  -name 'Pipfile' -o \
  -name 'poetry.lock' -o \
  -name 'pyproject.toml' -o \
  -name 'uv.lock' -o \
  -name 'Gemfile' -o \
  -name 'Gemfile.lock' -o \
  -name 'go.mod' -o \
  -name 'go.sum' -o \
  -name 'composer.json' -o \
  -name 'composer.lock' -o \
  -name 'Cargo.toml' -o \
  -name 'Cargo.lock' -o \
  -name 'packages.config' -o \
  -name '*.csproj' -o \
  -name '*.fsproj' -o \
  -name '*.vbproj' \
\) -print -quit | grep -q .; then
  echo "Snyk filesystem scan could not find supported target files in '$scan_location'."
  echo "Set 'location' to a directory containing manifests like package.json, pom.xml, build.gradle, requirements.txt, pyproject.toml, or go.mod."
  exit 1
fi

# Preflight Gradle projects to surface dependency/auth issues before Snyk wraps the failure.
gradle_manifest=$(find "$scan_location" -type f \( -name 'build.gradle' -o -name 'build.gradle.kts' \) -print -quit || true)
use_all_projects=true
if [[ -n "$gradle_manifest" ]]; then
  # For Gradle repositories, run without --all-projects as a compatibility workaround.
  use_all_projects=false
  gradle_dir=$(dirname "$gradle_manifest")
  gradlew_cmd=""
  if [[ -x "$gradle_dir/gradlew" ]]; then
    gradlew_cmd="$gradle_dir/gradlew"
  elif [[ -x "$scan_location/gradlew" ]]; then
    gradlew_cmd="$scan_location/gradlew"
  fi

  if [[ -n "$gradlew_cmd" ]]; then
    echo "Running Gradle preflight in '$gradle_dir' via '$gradlew_cmd'"
    set +e
    gradle_version_output=$("$gradlew_cmd" -v 2>/dev/null || true)
    gradle_major=$(printf '%s' "$gradle_version_output" | sed -n 's/^Gradle \([0-9][0-9]*\)\..*$/\1/p' | head -n1)
    snyk_version_output=$(snyk --version 2>/dev/null || true)
    snyk_major=$(printf '%s' "$snyk_version_output" | awk -F. '{print $1}')
    snyk_minor=$(printf '%s' "$snyk_version_output" | awk -F. '{print $2}')

    if [[ -n "$gradle_major" && "$gradle_major" -ge 9 ]]; then
      if [[ "$snyk_major" =~ ^[0-9]+$ ]] && [[ "$snyk_minor" =~ ^[0-9]+$ ]]; then
        if [[ "$snyk_major" -eq 1 && "$snyk_minor" -lt 1300 ]]; then
          echo "Detected Gradle ${gradle_major}.x with Snyk CLI ${snyk_version_output}."
          echo "This combination can fail with '--build-file' errors."
          echo "Update the centrally managed Snyk CLI version in this action or pin Gradle wrapper to 8.x for scanning."
        fi
      fi
    fi

    (
      cd "$gradle_dir"
      "$gradlew_cmd" -q help --no-daemon --stacktrace
    ) > gradle-preflight.log 2>&1
    gradle_preflight_exit=$?
    set -e
    if [[ $gradle_preflight_exit -ne 0 ]]; then
      echo "Gradle preflight failed before Snyk scan. This usually indicates dependency repository auth or build configuration issues."
      echo "Last 200 lines of gradle-preflight.log:"
      tail -n 200 gradle-preflight.log || true
      exit 2
    fi
  else
    echo "Gradle manifest detected but no executable gradlew found. Adding a Gradle wrapper is recommended for reliable CI dependency resolution."
  fi
fi

echo "Java runtime for fs scan:"
java -version || true

policy_path="$policy_path_input"
if [[ -z "$policy_path" ]]; then
  policy_path="$scan_location/.snyk"
fi
policy_arg=""
if [[ -f "$policy_path" ]]; then
  policy_arg="--policy-path=${policy_path}"
  echo "Applying Snyk policy file: ${policy_path}"
fi

set +e
if [[ "$use_all_projects" == "true" ]]; then
  snyk test "$scan_location" \
    --all-projects \
    --severity-threshold="$severity_threshold" \
    ${policy_arg:+$policy_arg} \
    --json-file-output=snyk-results.json \
    --sarif-file-output=snyk-results.sarif
else
  echo "Gradle project detected; running Snyk without --all-projects to avoid Gradle 9 compatibility issue."
  snyk test "$scan_location" \
    --severity-threshold="$severity_threshold" \
    ${policy_arg:+$policy_arg} \
    --json-file-output=snyk-results.json \
    --sarif-file-output=snyk-results.sarif
fi
cmd_exit=$?
set -e

if [[ $cmd_exit -eq 3 ]]; then
  echo "Snyk filesystem scan could not find supported target files in '$scan_location'."
  echo "Set 'location' to a directory containing supported manifests (for example pom.xml, build.gradle, package.json, requirements.txt)."
  exit $cmd_exit
fi

if [[ $cmd_exit -eq 2 ]]; then
  echo "Snyk filesystem scan failed to resolve dependencies (exit code 2)."
  echo "Common causes: private package repo credentials missing, Gradle/Maven auth config missing, missing ecosystem tools in runner, or project toolchain mismatch."
  echo "Re-running Snyk in debug mode to surface root cause..."

  set +e
  if [[ "$use_all_projects" == "true" ]]; then
    DEBUG='*snyk*' snyk test "$scan_location" \
      --all-projects \
      --severity-threshold="$severity_threshold" \
      ${policy_arg:+$policy_arg} \
      -d > snyk-debug.log 2>&1
  else
    DEBUG='*snyk*' snyk test "$scan_location" \
      --severity-threshold="$severity_threshold" \
      ${policy_arg:+$policy_arg} \
      -d > snyk-debug.log 2>&1
  fi
  set -e

  if grep -q '===== DEBUG INFORMATION START =====' snyk-debug.log; then
    echo "Snyk debug information block:"
    sed -n '/===== DEBUG INFORMATION START =====/,/===== DEBUG INFORMATION END =====/p' snyk-debug.log | tail -n 400 || true
  else
    echo "Last 200 lines of Snyk debug log:"
    tail -n 200 snyk-debug.log || true
  fi

  exit $cmd_exit
fi

if [[ $cmd_exit -gt 1 ]]; then
  echo "Snyk filesystem scan failed with exit code $cmd_exit"
  exit $cmd_exit
fi
