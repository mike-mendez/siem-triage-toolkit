# MITRE ATT&CK Mapping (Phase 4 Nginx Pack)

| Rule ID | Rule Name | ATT&CK Tactic | ATT&CK Technique |
|---|---|---|---|
| `nginx_sqli_querystring` | Nginx SQLi Pattern in Query String | Initial Access | T1190 - Exploit Public-Facing Application |
| `nginx_webshell_path_probe` | Nginx Webshell Path Probe | Persistence | T1505.003 - Web Shell |
| `nginx_404_recon_burst` | Nginx 404 Recon Burst to Sensitive Paths | Reconnaissance | T1595 - Active Scanning |
| `nginx_lfi_path_traversal_probe` | Nginx LFI Path Traversal Probe | Initial Access | T1190 - Exploit Public-Facing Application |
| `nginx_sensitive_file_access` | Nginx Sensitive File Access Attempt | Reconnaissance | T1595 - Active Scanning |
| `nginx_scanner_user_agent` | Nginx Known Scanner User-Agent | Reconnaissance | T1595 - Active Scanning |
| `nginx_login_bruteforce_burst` | Nginx Login Brute Force Burst | Credential Access | T1110 - Brute Force |
| `nginx_command_injection_query` | Nginx Command Injection Query Probe | Initial Access | T1190 - Exploit Public-Facing Application |
| `nginx_phpunit_eval_stdin_probe` | Nginx PHPUnit eval-stdin Probe | Initial Access | T1190 - Exploit Public-Facing Application |
| `nginx_xss_query_probe` | Nginx Reflected XSS Query Probe | Initial Access | T1190 - Exploit Public-Facing Application |

## Required Data Source
- Nginx access logs normalized to the field contract in:
  - `config/detections/field_contract.md`
