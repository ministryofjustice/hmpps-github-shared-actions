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
