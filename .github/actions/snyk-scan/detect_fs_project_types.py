import json
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


def read_first_nonempty_line(file_path):
  try:
    with open(file_path, 'r', encoding='utf-8') as file_handle:
      for raw_line in file_handle:
        line = raw_line.strip()
        if line and not line.startswith('#'):
          return line
  except OSError:
    return ''
  return ''


def find_first_file(location, file_name):
  direct_path = os.path.join(location, file_name)
  if os.path.isfile(direct_path):
    return direct_path

  for root, _, files in os.walk(location):
    if file_name in files:
      return os.path.join(root, file_name)
  return ''


def read_tool_versions_entry(location, tool_name):
  tool_versions_path = find_first_file(location, '.tool-versions')
  if not tool_versions_path:
    return ''

  try:
    with open(tool_versions_path, 'r', encoding='utf-8') as file_handle:
      for raw_line in file_handle:
        line = raw_line.strip()
        if not line or line.startswith('#'):
          continue

        parts = line.split()
        if len(parts) >= 2 and parts[0] == tool_name:
          return parts[1]
  except OSError:
    return ''

  return ''


def detect_ruby_version_from_rubocop(location):
  rubocop_path = find_first_file(location, '.rubocop.yml')
  if not rubocop_path:
    return ''

  try:
    with open(rubocop_path, 'r', encoding='utf-8') as file_handle:
      for raw_line in file_handle:
        line = raw_line.strip()
        if not line or line.startswith('#') or 'TargetRubyVersion' not in line:
          continue

        key, separator, value = line.partition(':')
        if separator and key.strip() == 'TargetRubyVersion':
          parsed = value.strip().strip('"\'')
          if parsed:
            return parsed
  except OSError:
    return ''

  return ''


def detect_ruby_version_from_gemfile_lock(location):
  gemfile_lock_path = find_first_file(location, 'Gemfile.lock')
  if not gemfile_lock_path:
    return ''

  try:
    with open(gemfile_lock_path, 'r', encoding='utf-8') as file_handle:
      in_ruby_version_block = False
      for raw_line in file_handle:
        line = raw_line.rstrip('\n')
        stripped = line.strip()

        if stripped == 'RUBY VERSION':
          in_ruby_version_block = True
          continue

        if in_ruby_version_block:
          if not stripped:
            continue

          if not line.startswith(' ') and not line.startswith('\t'):
            break

          if stripped.startswith('ruby '):
            parts = stripped.split()
            if len(parts) >= 2:
              version = parts[1].split('p')[0]
              if version:
                return version
            break
  except OSError:
    return ''

  return ''


def detect_ruby_version(location):
  ruby_version_path = find_first_file(location, '.ruby-version')
  if ruby_version_path:
    ruby_version = read_first_nonempty_line(ruby_version_path)
    if ruby_version.startswith('ruby-'):
      ruby_version = ruby_version[5:]
    if ruby_version:
      return ruby_version

  ruby_version = read_tool_versions_entry(location, 'ruby')
  if ruby_version:
    return ruby_version

  ruby_version = detect_ruby_version_from_rubocop(location)
  if ruby_version:
    return ruby_version

  return detect_ruby_version_from_gemfile_lock(location)


def detect_java_version(location):
  java_version_path = find_first_file(location, '.java-version')
  if java_version_path:
    java_version = read_first_nonempty_line(java_version_path)
    if java_version:
      return java_version

  return read_tool_versions_entry(location, 'java')


def detect_go_version(location):
  go_mod_path = find_first_file(location, 'go.mod')
  if go_mod_path:
    try:
      with open(go_mod_path, 'r', encoding='utf-8') as file_handle:
        for raw_line in file_handle:
          line = raw_line.strip()
          if line.startswith('go '):
            parts = line.split()
            if len(parts) >= 2:
              return parts[1]
    except OSError:
      pass

  go_version = read_tool_versions_entry(location, 'golang')
  if go_version:
    return go_version

  return read_tool_versions_entry(location, 'go')


def detect_dotnet_version(location):
  global_json_path = find_first_file(location, 'global.json')
  if global_json_path:
    try:
      with open(global_json_path, 'r', encoding='utf-8') as file_handle:
        data = json.load(file_handle)
        sdk = data.get('sdk') if isinstance(data, dict) else None
        version = sdk.get('version') if isinstance(sdk, dict) else ''
        if isinstance(version, str) and version.strip():
          return version.strip()
    except (OSError, json.JSONDecodeError):
      pass

  return read_tool_versions_entry(location, 'dotnet')


def main():
  scan_location = sys.argv[1] if len(sys.argv) > 1 else '.'

  if not os.path.isdir(scan_location):
    print(f"Filesystem scan location does not exist: '{scan_location}'", file=sys.stderr)
    sys.exit(1)

  project_type = 'unknown'
  ruby_version = ''
  java_version = ''
  go_version = ''
  dotnet_version = ''

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

  if project_type == 'ruby':
    ruby_version = detect_ruby_version(scan_location)

  if project_type in {'gradle', 'maven'}:
    java_version = detect_java_version(scan_location)

  if project_type == 'go':
    go_version = detect_go_version(scan_location)

  if project_type == 'dotnet':
    dotnet_version = detect_dotnet_version(scan_location)

  print(f'project_type={project_type}')
  if project_type in {'gradle', 'maven'}:
    print(f'java_version={java_version}')
  elif project_type == 'ruby':
    print(f'ruby_version={ruby_version}')
  elif project_type == 'go':
    print(f'go_version={go_version}')
  elif project_type == 'dotnet':
    print(f'dotnet_version={dotnet_version}')


if __name__ == '__main__':
  main()