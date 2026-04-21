#!/bin/bash

set -ueo pipefail

# Validate required environment variables
REPOSITORY_NAME="${GITHUB_REPOSITORY#*/}"

if [[ -z "${SHAREPOINT_SITE_URL}" || -z "${SHAREPOINT_FOLDER_URL}" || -z "${SP_CLIENT_ID}" || -z "${SP_CLIENT_SECRET}" || -z "${AZ_TENANT_ID}" || -z "${RETENTION_COUNT}" || -z "${ARCHIVE_PATH}" ]]; then
  echo "Error: Missing required environment variables" >&2
  exit 1
fi

# Validate retention count
if ! [[ "${RETENTION_COUNT}" =~ ^[0-9]+$ ]] || [[ "${RETENTION_COUNT}" -lt 1 ]]; then
  echo "Error: retention_count must be a positive integer" >&2
  exit 1
fi

# Validate archive file exists
if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  echo "Error: Archive file not found: ${ARCHIVE_PATH}" >&2
  exit 1
fi

SHAREPOINT_ACCESS_TOKEN=""
GRAPH_SITE_ID=""
GRAPH_DRIVE_ID=""
GRAPH_DOC_LIBRARY="Documents"

get_access_token() {
  echo "Fetching Graph access token from Azure AD..."

  TOKEN_RESPONSE=$(curl -sS -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=${SP_CLIENT_ID}" \
    -d "client_secret=${SP_CLIENT_SECRET}" \
    -d "scope=https://graph.microsoft.com/.default" \
    "https://login.microsoftonline.com/${AZ_TENANT_ID}/oauth2/v2.0/token")

  SHAREPOINT_ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

  if [[ "${SHAREPOINT_ACCESS_TOKEN}" == "null" ]] || [[ -z "${SHAREPOINT_ACCESS_TOKEN}" ]]; then
    echo "Error: Failed to fetch Graph access token." >&2
    echo "$TOKEN_RESPONSE" >&2
    exit 1
  fi

  echo "Graph access token fetched successfully."
}

init_graph_context() {
  echo "Resolving Graph site and drive IDs..."

  # Parse site URL to extract host and site path
  GRAPH_HOST=$(echo "${SHAREPOINT_SITE_URL}" | sed -E 's|https?://([^/]+)/.*|\1|')
  GRAPH_SITE_PATH=$(echo "${SHAREPOINT_SITE_URL}" | sed -E 's|https?://[^/]+/sites/||')

  SITE_RESPONSE=$(curl -sS -X GET \
    -H "Authorization: Bearer ${SHAREPOINT_ACCESS_TOKEN}" \
    -H "Accept: application/json" \
    "https://graph.microsoft.com/v1.0/sites/${GRAPH_HOST}:/sites/${GRAPH_SITE_PATH}?\$select=id")

  GRAPH_SITE_ID=$(echo "$SITE_RESPONSE" | jq -r '.id')
  if [[ "${GRAPH_SITE_ID}" == "null" ]] || [[ -z "${GRAPH_SITE_ID}" ]]; then
    echo "Error: Failed to resolve Graph site id." >&2
    echo "$SITE_RESPONSE" >&2
    exit 1
  fi

  DRIVES_RESPONSE=$(curl -sS -X GET \
    -H "Authorization: Bearer ${SHAREPOINT_ACCESS_TOKEN}" \
    -H "Accept: application/json" \
    "https://graph.microsoft.com/v1.0/sites/${GRAPH_SITE_ID}/drives?\$select=id,name")

  GRAPH_DRIVE_ID=$(echo "$DRIVES_RESPONSE" | jq -r --arg name "$GRAPH_DOC_LIBRARY" '.value[] | select(.name==$name) | .id' | head -n1)

  if [[ -z "${GRAPH_DRIVE_ID}" ]] || [[ "${GRAPH_DRIVE_ID}" == "null" ]]; then
    echo "Error: Could not find document library '${GRAPH_DOC_LIBRARY}'." >&2
    echo "$DRIVES_RESPONSE" >&2
    exit 1
  fi

  echo "Graph context resolved successfully."
}

upload_to_sharepoint() {
  local FILE_PATH="$1"
  local FILE_NAME=$(basename "${FILE_PATH}")
  
  echo "Uploading ${FILE_NAME} to SharePoint..."

  UPLOAD_URL="https://graph.microsoft.com/v1.0/drives/${GRAPH_DRIVE_ID}/root:${SHAREPOINT_FOLDER_URL}/${FILE_NAME}:/content"

  HTTP_CODE=$(curl -sS -o /tmp/graph_upload_response.json -w "%{http_code}" -X PUT \
      -H "Authorization: Bearer ${SHAREPOINT_ACCESS_TOKEN}" \
      -H "Content-Type: application/octet-stream" \
      --data-binary @"${FILE_PATH}" \
      "${UPLOAD_URL}")

  if [[ "${HTTP_CODE}" -lt 200 ]] || [[ "${HTTP_CODE}" -ge 300 ]]; then
    echo "Error during upload of ${FILE_NAME}. HTTP ${HTTP_CODE}" >&2
    cat /tmp/graph_upload_response.json >&2
    exit 1
  else
    echo "Successfully uploaded ${FILE_NAME}."
  fi
}

enforce_retention() {
  echo "Enforcing retention policy: keeping latest ${RETENTION_COUNT} backup(s)..."

  LIST_FILES_URL="https://graph.microsoft.com/v1.0/drives/${GRAPH_DRIVE_ID}/root:${SHAREPOINT_FOLDER_URL}:/children?\$select=id,name,lastModifiedDateTime"
  RESPONSE=$(curl -sS -X GET \
      -H "Authorization: Bearer ${SHAREPOINT_ACCESS_TOKEN}" \
      -H "Accept: application/json" \
      "${LIST_FILES_URL}")

  # Filter files matching repository prefix and .tar.gz extension
  MATCHING_FILES=$(echo "$RESPONSE" | jq -r --arg prefix "${REPOSITORY_NAME}-" '.value[] | select(.name | startswith($prefix) and endswith(".tar.gz")) | @json')

  # Convert to array and sort by modification time (oldest first)
  mapfile -t FILES_ARRAY < <(echo "$MATCHING_FILES" | jq -s -r 'sort_by(.lastModifiedDateTime) | .[] | @base64')

  TOTAL_FILES=${#FILES_ARRAY[@]}
  echo "Found ${TOTAL_FILES} backup(s) for repository ${REPOSITORY_NAME}."

  if [[ ${TOTAL_FILES} -le ${RETENTION_COUNT} ]]; then
    echo "Retention check complete: ${TOTAL_FILES} backup(s) found, no deletion required (limit ${RETENTION_COUNT})."
    return 0
  fi

  # Calculate how many files to delete
  FILES_TO_DELETE=$((TOTAL_FILES - RETENTION_COUNT))
  echo "Deleting ${FILES_TO_DELETE} old backup(s) to enforce retention..."

  # Delete oldest files
  for ((i = 0; i < FILES_TO_DELETE; i++)); do
    FILE_JSON=$(echo "${FILES_ARRAY[$i]}" | base64 -d)
    FILE_ID=$(echo "$FILE_JSON" | jq -r '.id')
    FILE_NAME=$(echo "$FILE_JSON" | jq -r '.name')
    FILE_MODIFIED=$(echo "$FILE_JSON" | jq -r '.lastModifiedDateTime')

    DELETE_URL="https://graph.microsoft.com/v1.0/drives/${GRAPH_DRIVE_ID}/items/${FILE_ID}"
    echo "Deleting file ${FILE_NAME} (modified: ${FILE_MODIFIED})..."

    DELETE_HTTP_CODE=$(curl -sS -o /tmp/graph_delete_response.json -w "%{http_code}" -X DELETE \
        -H "Authorization: Bearer ${SHAREPOINT_ACCESS_TOKEN}" \
        "${DELETE_URL}")

    if [[ "${DELETE_HTTP_CODE}" -ne 204 ]] && [[ "${DELETE_HTTP_CODE}" -ne 200 ]]; then
      echo "Error deleting file ${FILE_NAME}. HTTP ${DELETE_HTTP_CODE}" >&2
      cat /tmp/graph_delete_response.json >&2
    else
      echo "Successfully deleted file ${FILE_NAME}."
    fi
  done

  echo "Retention check complete: kept latest ${RETENTION_COUNT} backup(s) for repository ${REPOSITORY_NAME}."
}

# Main execution
get_access_token
init_graph_context
upload_to_sharepoint "${ARCHIVE_PATH}"
enforce_retention

echo "Repository backup and retention completed successfully."
