#!/usr/bin/env bash
set -euo pipefail

scan_location="${1:-.}"

if [[ ! -d "$scan_location" ]]; then
  echo "Filesystem scan location does not exist: '$scan_location'" >&2
  exit 1
fi

has_file() {
  local location="$1"
  local expr="$2"
  if eval "find \"$location\" -type f \( $expr \) -print -quit" | grep -q .; then
    echo true
  else
    echo false
  fi
}

project_type="unknown"

if [[ "$(has_file "$scan_location" "-name 'build.gradle' -o -name 'build.gradle.kts' -o -name 'settings.gradle' -o -name 'settings.gradle.kts'")" == "true" ]]; then
  project_type="gradle"
elif [[ "$(has_file "$scan_location" "-name 'pom.xml'")" == "true" ]]; then
  project_type="maven"
elif [[ "$(has_file "$scan_location" "-name 'uv.lock'")" == "true" ]]; then
  project_type="uv"
elif [[ "$(has_file "$scan_location" "-name 'go.mod' -o -name 'go.sum'")" == "true" ]]; then
  project_type="go"
elif [[ "$(has_file "$scan_location" "-name '*.csproj' -o -name '*.fsproj' -o -name '*.vbproj' -o -name 'packages.config'")" == "true" ]]; then
  project_type="dotnet"
elif [[ "$(has_file "$scan_location" "-name 'Gemfile' -o -name 'Gemfile.lock'")" == "true" ]]; then
  project_type="ruby"
elif [[ "$(has_file "$scan_location" "-name 'composer.json' -o -name 'composer.lock'")" == "true" ]]; then
  project_type="php"
elif [[ "$(has_file "$scan_location" "-name 'Cargo.toml' -o -name 'Cargo.lock'")" == "true" ]]; then
  project_type="rust"
elif [[ "$(has_file "$scan_location" "-name 'package.json' -o -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml'")" == "true" ]]; then
  project_type="node"
elif [[ "$(has_file "$scan_location" "-name 'requirements.txt' -o -name 'Pipfile' -o -name 'poetry.lock' -o -name 'pyproject.toml'")" == "true" ]]; then
  project_type="python"
fi

echo "project_type=${project_type}"
