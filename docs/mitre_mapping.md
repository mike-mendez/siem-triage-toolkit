# MITRE ATT&CK Mapping (Phase 2 Nginx Pack)

| Rule ID | Rule Name | ATT&CK Tactic | ATT&CK Technique |
|---|---|---|---|
| `nginx_sqli_querystring` | Nginx SQLi Pattern in Query String | Initial Access | T1190 - Exploit Public-Facing Application |
| `nginx_webshell_path_probe` | Nginx Webshell Path Probe | Persistence | T1505.003 - Web Shell |
| `nginx_404_recon_burst` | Nginx 404 Recon Burst to Sensitive Paths | Reconnaissance | T1595 - Active Scanning |

## Required Data Source
- Nginx access logs normalized to the field contract in:
  - `config/detections/field_contract.md`
