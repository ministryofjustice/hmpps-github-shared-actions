# hmpps-github-shared-actions
Shared actions for Github workflows to use 

This is to ensure we can use SHA pinning to access them.

DO NOT PUT ANY SHARED WORKFLOWS HERE!  (workflows in this repo are for CI testing or building code in this particular repository.)

## Repository Backup to SharePoint

Use `.github/actions/sharepoint_repository_backup` to create a `.tar.gz` backup of the calling repository and upload it to SharePoint with automatic retention cleanup.

**Backup structure:** `Documents/RepositoryBackup/{repository-name}/`

**Retention:** Configurable via `retention_count` input (defaults to `5` — keeps the 5 most recent backups).

**Setup:** Org-level secrets are inherited automatically by all consuming repositories.

Example usage from a consumer repository workflow:

```yaml
jobs:
  backup:
    name: Backup to SharePoint
    runs-on: ubuntu-latest
    env:
      SP_CLIENT_ID: ${{ secrets.SHAREPOINT_CLIENT_ID }}
      SP_CLIENT_SECRET: ${{ secrets.SHAREPOINT_CLIENT_SECRET }}
      AZ_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
    steps:
      - name: Backup repository to SharePoint
        uses: ministryofjustice/hmpps-github-shared-actions/.github/actions/sharepoint_repository_backup@v1
        with:
          retention_count: 5   # optional, defaults to 5
```

**Repository level secrets required:**

- `SP_CLIENT_ID` — Azure app registration client ID
- `SP_CLIENT_SECRET` — Azure app registration client secret
- `AZ_TENANT_ID` — Azure tenant ID

**Repository level variables (optional):**

- `GRAPH_HOST` — SharePoint host domain (defaults to `justiceuk.sharepoint.com` if not provided)
- `GRAPH_SITE_PATH` — SharePoint site path (defaults to `HMPPSSRE` if not provided)

**Site configuration:**

- Default SharePoint Site: `https://justiceuk.sharepoint.com/sites/HMPPSSRE`
- Document Library: `Documents`
- Folder Path: `Documents/RepositoryBackup/{repository-name}`
