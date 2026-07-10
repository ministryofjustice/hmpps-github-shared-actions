# hmpps-github-shared-actions

Reusable composite GitHub Actions for HMPPS repositories.

Use these actions from consumer repositories with pinned refs (tag or commit SHA).

This repository is for shared actions only. Do not add shared workflows here.

## Available actions

### Security and scanning

| Action path | Name | Description |
| --- | --- | --- |
| `.github/actions/snyk-scan` | Snyk Security Scan | Run Snyk vulnerability scanning with configurable options for image and filesystem scans. |
| `.github/actions/auditjson_to_sarif` | Convert NPM Audit to SARIF | Converts npm audit-ci JSON output to SARIF format. |
| `.github/actions/auditjson_to_slack` | Convert NPM Audit to a table suitable for Slack | Converts npm audit-ci JSON output to a presentable table. |
| `.github/actions/security_npm_outdated` | Create and upload npm outdated reports | Creates and uploads npm outdated reports. |
| `.github/actions/security_veracode_prepare_artifacts` | veracode prepare artifacts | Collects application artifacts and creates a zip for Veracode SAST scan. |

### Slack notifications

| Action path | Name | Description |
| --- | --- | --- |
| `.github/actions/slack_snyk_scan_notification` | Snyk Scan Slack message for failure or findings | Sends Slack message for Snyk failure/findings with optional generated summary. |
| `.github/actions/slack_codescan_notification` | failure Slack message | Sends a Slack message to notify of failure. |
| `.github/actions/slack_failure_results` | failure Slack message | Sends a Slack message based on an uploaded file. |
| `.github/actions/slack_prepare_results` | prepare slack message | Converts output/results text into a Slack-compatible variable. |
| `.github/actions/slack_release_results` | send a slack release message | Sends release status message to Slack for channel/environment. |
| `.github/actions/version_history` | get the commit history | Gets commits since last deployment for Slack release notes. |

### Build and deployment helpers

| Action path | Name | Description |
| --- | --- | --- |
| `.github/actions/build-test-and-deploy/build_docker` | Build and push docker image to registry | Builds and pushes Docker image. |
| `.github/actions/build-test-and-deploy/cloud-platform-auth` | Cloud Platform Auth | Authenticates with MOJ Cloud Platform. |
| `.github/actions/build-test-and-deploy/cloud-platform-deploy` | Cloud Platform Deploy | Deploys to Cloud Platform using Helm. |
| `.github/actions/build-test-and-deploy/create_app_version` | Create app version to use it for docker build and deploy pipelines | Creates app version for build/deploy pipelines. |

### Tool installers

| Action path | Name | Description |
| --- | --- | --- |
| `.github/actions/tool-installers/setup-helm` | Setup Helm | Installs Helm with checksum verification. |
| `.github/actions/tool-installers/setup-kubectl` | Setup kubectl | Installs kubectl with checksum verification. |
| `.github/actions/tool-installers/setup-veracode-wrapper` | Setup Veracode Wrapper | Downloads Veracode Java API wrapper with checksum verification. |
| `.github/actions/tool-installers/setup-wiremock` | Setup WireMock | Downloads WireMock standalone JAR with checksum verification. |

### Data and backup utilities

| Action path | Name | Description |
| --- | --- | --- |
| `.github/actions/database_schema_report` | Generate postgres database schema report | Generates Postgres schema report (requires Postgres in pipeline). |
| `.github/actions/sharepoint_repository_backup` | Backup repository to SharePoint | Archives calling repository and uploads to SharePoint with retention cleanup. |

## Snyk scan action quick reference

Action path: `.github/actions/snyk-scan`

Key behavior:

- Supports `scan_type: image` (default) and `scan_type: fs`.
- For image scans, uses `image_ref` when provided.
- If `image_ref` is empty, it attempts to resolve image repository from `values.yaml`.
- GHCR login occurs when image scan target is GHCR, including when `image_ref` starts with `ghcr.io/`.
- Exposes vulnerability counts and summary as action outputs.

Authentication inputs:

- OAuth client credentials via `client_id` and `client_secret`, or
- Token auth via `snyk_token`.

## Slack Snyk notification quick reference

Action path: `.github/actions/slack_snyk_scan_notification`

Project field behavior:

- If `image_ref` is provided, project is derived from image name in `image_ref`.
  - Example: `ghcr.io/ministryofjustice/hmpps-clamav:c793...` -> `hmpps-clamav`
- If `image_ref` is not provided, project falls back to:
  - `subproject` when set, otherwise
  - repository name.

Summary behavior:

- Uses provided `summary` when valid.
- If summary is empty or boolean-like, attempts to generate summary/findings from `snyk-results.json`.

## SharePoint repository backup

Action path: `.github/actions/sharepoint_repository_backup`

Use this action to create a `.tar.gz` backup of the calling repository and upload to SharePoint.

- Backup structure: `Documents/RepositoryBackup/{repository-name}/`
- Retention: configurable via `retention_count` (default `5`)

Required secrets:

- `SP_CLIENT_ID`
- `SP_CLIENT_SECRET`
- `AZ_TENANT_ID`

Optional variables:

- `GRAPH_HOST` (default `justiceuk.sharepoint.com`)
- `GRAPH_SITE_PATH` (default `HMPPSSRE`)

## Basic usage pattern

```yaml
jobs:
  example:
    runs-on: ubuntu-latest
    steps:
      - name: Run shared action
        uses: ministryofjustice/hmpps-github-shared-actions/.github/actions/snyk-scan@<SHA>
        with:
          scan_type: image
          image_ref: ghcr.io/ministryofjustice/my-image:latest
```
