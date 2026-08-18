import os
import sys  


def has_file(location, names):
  for root, _, files in os.walk(location):
    for file_name in files:
      if file_name in names:
        return True
  return False


def has_suffix_file(location, suffixes):
  for root, _, files in os.walk(location):
    for file_name in files:
      for suffix in suffixes:
        if file_name.endswith(suffix):
          return True
  return False


def main():
  scan_location = sys.argv[1] if len(sys.argv) > 1 else '.'

  if not os.path.isdir(scan_location):
    print(f"Filesystem scan location does not exist: '{scan_location}'", file=sys.stderr)
    sys.exit(1)

  project_type = 'unknown'

  if has_file(scan_location, {'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'}):
    project_type = 'gradle'
  elif has_file(scan_location, {'pom.xml'}):
    project_type = 'maven'
  elif has_file(scan_location, {'uv.lock'}):
    project_type = 'uv'
  elif has_file(scan_location, {'go.mod', 'go.sum'}):
    project_type = 'go'
  elif has_file(scan_location, {'packages.config'}) or has_suffix_file(scan_location, {'.csproj', '.fsproj', '.vbproj'}):
    project_type = 'dotnet'
  elif has_file(scan_location, {'Gemfile', 'Gemfile.lock'}):
    project_type = 'ruby'
  elif has_file(scan_location, {'composer.json', 'composer.lock'}):
    project_type = 'php'
  elif has_file(scan_location, {'Cargo.toml', 'Cargo.lock'}):
    project_type = 'rust'
  elif has_file(scan_location, {'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'}):
    project_type = 'node'
  elif has_file(scan_location, {'requirements.txt', 'Pipfile', 'poetry.lock', 'pyproject.toml'}):
    project_type = 'python'

  print(f'project_type={project_type}')


if __name__ == '__main__':
  main()