# Wiz Container Scanning

Container security scanning using [Wiz](https://www.wiz.io) CLI with SARIF upload to GitHub Code Scanning.

## What it does

1. **Builds** a Docker image from the Dockerfile
2. **Scans** the image using `wizcli docker scan`
3. **Enriches** the SARIF output with security-severity CVSS scores (PS1 parser)
4. **Uploads** enriched SARIF to GitHub Security tab (Code Scanning alerts)
5. **Generates** a Job Summary markdown report

## Secrets Required

| Secret | Description |
|---|---|
| `WIZ_CLIENT_ID` | Wiz service account client ID |
| `WIZ_CLIENT_SECRET` | Wiz service account client secret |

## Workflow

The `.github/workflows/wiz.yml` runs on push/PR to main branches.

## SARIF Parser

`scripts/parse_wiz_image_scan.ps1` enriches the raw Wiz SARIF with:
- `security-severity` CVSS scores (CRITICAL=9.5, HIGH=8.0, MEDIUM=5.5, LOW=3.0)
- Enriched alert titles with package name and version
- `[Wiz Cloud]` prefixed rule names for GitHub Security tab
- GitHub Job Summary markdown report
