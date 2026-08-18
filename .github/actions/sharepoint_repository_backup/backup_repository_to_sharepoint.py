import json
import logging
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger(__name__)

def require_env(name):
  value = os.getenv(name, '').strip()
  if not value:
    log.error('Error: Missing required environment variables')
    sys.exit(1)
  return value


def graph_request(method, url, token=None, headers=None, data=None):
  req_headers = {'Accept': 'application/json'}
  if token:
    req_headers['Authorization'] = f'Bearer {token}'
  if headers:
    req_headers.update(headers)

  req = Request(url=url, method=method, headers=req_headers, data=data)
  try:
    with urlopen(req) as resp:
      body = resp.read().decode('utf-8', errors='replace')
      return resp.getcode(), body
  except HTTPError as err:
    body = err.read().decode('utf-8', errors='replace')
    return err.code, body
  except URLError as err:
    log.error(f'Error: Network error calling Microsoft Graph: {err}')
    sys.exit(1)


def parse_json(raw, context):
  try:
    return json.loads(raw) if raw else {}
  except json.JSONDecodeError:
    log.error(f'Error: Failed to parse JSON response while {context}')
    sys.exit(1)


def get_access_token(tenant_id, client_id, client_secret):
  log.info('Fetching Graph access token from Azure AD...')

  token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
  form_body = urlencode(
    {
      'grant_type': 'client_credentials',
      'client_id': client_id,
      'client_secret': client_secret,
      'scope': 'https://graph.microsoft.com/.default',
    }
  ).encode('utf-8')

  status, body = graph_request(
    'POST',
    token_url,
    headers={'Content-Type': 'application/x-www-form-urlencoded'},
    data=form_body,
  )

  if status < 200 or status >= 300:
    log.error('Error: Failed to fetch Graph access token.')
    log.error(body)
    sys.exit(1)

  parsed = parse_json(body, 'fetching access token')
  access_token = parsed.get('access_token')
  if not access_token:
    log.error('Error: Failed to fetch Graph access token.')
    log.error(body)
    sys.exit(1)

  log.info('Graph access token fetched successfully.')
  return access_token


def init_graph_context(access_token, graph_host, graph_site_path, graph_doc_library):
  log.info('Resolving Graph site and drive IDs...')

  site_url = f'https://graph.microsoft.com/v1.0/sites/{graph_host}:/sites/{graph_site_path}?$select=id'
  site_status, site_body = graph_request('GET', site_url, token=access_token)
  site_payload = parse_json(site_body, 'resolving site id')
  site_id = site_payload.get('id')
  if site_status < 200 or site_status >= 300 or not site_id:
    log.error('Error: Failed to resolve Graph site id.')
    log.error(site_body)
    sys.exit(1)

  drives_url = f'https://graph.microsoft.com/v1.0/sites/{site_id}/drives?$select=id,name'
  drives_status, drives_body = graph_request('GET', drives_url, token=access_token)
  drives_payload = parse_json(drives_body, 'resolving drive id')
  if drives_status < 200 or drives_status >= 300:
    log.error('Error: Failed to list drives for site.')
    log.error(drives_body)
    sys.exit(1)

  drive_id = ''
  for drive in drives_payload.get('value', []):
    if drive.get('name') == graph_doc_library:
      drive_id = drive.get('id', '')
      break

  if not drive_id:
    log.error(f"Error: Could not find document library '{graph_doc_library}'.")
    log.error(drives_body)
    sys.exit(1)

  log.debug(f'Graph context resolved successfully. Site ID: {site_id}, Drive ID: {drive_id}')
  return site_id, drive_id


def ensure_folder_exists(access_token, drive_id, folder_path):
  log.info(f"Ensuring folder '{folder_path}' exists in drive...")

  encoded_path = quote(folder_path, safe='/')
  check_url = f'https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{encoded_path}'
  status, body = graph_request('GET', check_url, token=access_token)

  if status == 200:
    log.info('Folder already exists.')
    return

  if status != 404:
    log.error(f'Error: Unexpected response checking folder. HTTP {status}')
    log.error(body)
    sys.exit(1)

  log.info(f"Folder not found, creating '{folder_path}'...")

  parent_path = ''
  for segment in folder_path.split('/'):
    if not segment:
      continue

    if not parent_path:
      create_url = f'https://graph.microsoft.com/v1.0/drives/{drive_id}/root/children'
    else:
      encoded_parent = quote(parent_path, safe='/')
      create_url = f'https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{encoded_parent}:/children'

    payload = {
      'name': segment,
      'folder': {},
      '@microsoft.graph.conflictBehavior': 'replace',
    }
    create_status, create_body = graph_request(
      'POST',
      create_url,
      token=access_token,
      headers={'Content-Type': 'application/json'},
      data=json.dumps(payload).encode('utf-8'),
    )

    if create_status < 200 or create_status >= 300:
      log.error(f"Error: creating folder segment '{segment}'. HTTP {create_status}")
      log.error(create_body)
      sys.exit(1)

    parent_path = segment if not parent_path else f'{parent_path}/{segment}'

  log.info(f"Folder '{folder_path}' created successfully.")


def upload_to_sharepoint(access_token, drive_id, folder_path, file_path):
  file_name = os.path.basename(file_path)
  log.info(f'Uploading {file_name} to SharePoint...')

  encoded_folder = quote(folder_path, safe='/')
  encoded_name = quote(file_name)
  upload_url = f'https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{encoded_folder}/{encoded_name}:/content'

  with open(file_path, 'rb') as f:
    binary_data = f.read()

  status, body = graph_request(
    'PUT',
    upload_url,
    token=access_token,
    headers={'Content-Type': 'application/octet-stream'},
    data=binary_data,
  )

  if status < 200 or status >= 300:
    log.error(f'Error: during upload of {file_name}. HTTP {status}')
    log.error(body)
    sys.exit(1)

  log.info(f'Successfully uploaded {file_name}.')


def enforce_retention(access_token, drive_id, folder_path, repository_name, retention_count):
  log.info(f'Enforcing retention policy: keeping latest {retention_count} backup(s)...')

  encoded_folder = quote(folder_path, safe='/')
  list_url = f'https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{encoded_folder}:/children?$select=id,name,lastModifiedDateTime'
  status, body = graph_request('GET', list_url, token=access_token)
  if status < 200 or status >= 300:
    log.error(f'Error: Failed to list files for retention. HTTP {status}')
    log.error(body)
    sys.exit(1)

  payload = parse_json(body, 'listing backup files')
  prefix = f'{repository_name}-'
  matching_files = []
  for item in payload.get('value', []):
    name = item.get('name', '')
    if name.startswith(prefix) and name.endswith('.tar.gz'):
      matching_files.append(item)

  matching_files.sort(key=lambda x: x.get('lastModifiedDateTime', ''))
  total_files = len(matching_files)
  log.info(f'Found {total_files} backup(s) for repository {repository_name}.')

  if total_files <= retention_count:
    log.info(
      f'Retention check complete: {total_files} backup(s) found, no deletion required (limit {retention_count}).'
    )
    return

  files_to_delete = total_files - retention_count
  log.info(f'Deleting {files_to_delete} old backup(s) to enforce retention...')

  for item in matching_files[:files_to_delete]:
    file_id = item.get('id', '')
    file_name = item.get('name', '<unknown>')
    file_modified = item.get('lastModifiedDateTime', '<unknown>')
    delete_url = f'https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{file_id}'

    log.info(f'Deleting file {file_name} (modified: {file_modified})...')
    delete_status, delete_body = graph_request('DELETE', delete_url, token=access_token)

    if delete_status not in (200, 204):
      log.error(f'Error: deleting file {file_name}. HTTP {delete_status}')
      log.error(delete_body)
    else:
      log.info(f'Successfully deleted file {file_name}.')

  log.info(f'Retention check complete: kept latest {retention_count} backup(s) for repository {repository_name}.')


def main():
  github_repository = require_env('GITHUB_REPOSITORY')
  repository_name = github_repository.split('/', 1)[1] if '/' in github_repository else github_repository

  client_id = require_env('SP_CLIENT_ID')
  client_secret = require_env('SP_CLIENT_SECRET')
  tenant_id = require_env('AZ_TENANT_ID')
  retention_count_raw = require_env('RETENTION_COUNT')
  archive_path = require_env('ARCHIVE_PATH')

  if not retention_count_raw.isdigit() or int(retention_count_raw) < 1:
    log.error('Error: retention_count must be a positive integer')
    sys.exit(1)
  retention_count = int(retention_count_raw)

  if not os.path.isfile(archive_path):
    log.error(f'Error: Archive file not found: {archive_path}')
    sys.exit(1)

  graph_host = os.getenv('GRAPH_HOST', 'justiceuk.sharepoint.com')
  graph_site_path = os.getenv('GRAPH_SITE_PATH', 'HMPPSSRE')
  graph_doc_library = 'Documents'
  folder_path = f'RepositoryBackup/{repository_name}'

  access_token = get_access_token(tenant_id, client_id, client_secret)
  _, drive_id = init_graph_context(access_token, graph_host, graph_site_path, graph_doc_library)
  ensure_folder_exists(access_token, drive_id, folder_path)
  upload_to_sharepoint(access_token, drive_id, folder_path, archive_path)
  enforce_retention(access_token, drive_id, folder_path, repository_name, retention_count)

  log.info('Repository backup and retention completed successfully.')


if __name__ == '__main__':
  main()
