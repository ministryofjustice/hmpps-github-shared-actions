# hmpps-github-shared-actions
Shared actions for Github workflows to use 

This is to ensure we can use SHA pinning to access them.

DO NOT PUT ANY SHARED WORKFLOWS HERE!  (workflows in this repo are for CI testing or building code in this particular repository.)

## Repository Backup to SharePoint

Use `.github/actions/sharepoint_repository_backup` to create a `.tar.gz` backup of the calling repository and upload it to SharePoint.

Retention is configurable with `retention_count` and defaults to `5`.

Example usage from a consumer repository workflow:

```yaml
jobs:
  backup-repository:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6

      - name: Backup repository to SharePoint
        uses: ministryofjustice/hmpps-github-shared-actions/.github/actions/sharepoint_repository_backup@<sha>
        with:
          sharepoint_site_url: ${{ secrets.SHAREPOINT_SITE_URL }}
          sharepoint_folder_server_relative_url: ${{ secrets.SHAREPOINT_FOLDER_SERVER_RELATIVE_URL }}
          sharepoint_client_id: ${{ secrets.SHAREPOINT_CLIENT_ID }}
          sharepoint_client_secret: ${{ secrets.SHAREPOINT_CLIENT_SECRET }}
          azure_tenant_id: ${{ secrets.AZURE_TENANT_ID }}
          retention_count: 5
```

Suggested org-level secrets:

- `SHAREPOINT_SITE_URL`
- `SHAREPOINT_FOLDER_SERVER_RELATIVE_URL`
- `SHAREPOINT_CLIENT_ID`
- `SHAREPOINT_CLIENT_SECRET`
- `AZURE_TENANT_ID`
