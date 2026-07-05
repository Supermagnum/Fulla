# Adversarial security test results (executed)

Real results from the Docker adversarial harness. Not predicted or static-review output.

**Last full run:** 2026-07-05 (operational hardening: supply chain, scanners, spam limits, extension integrity)  
**Repository:** Fulla @ security hardening round 12  
**Runner:** `./docker/run-adversarial.sh` (4 stages)  
**Summary:** supply-chain pass (Marvin reachability traced); trivy/nikto/sqlmap executed against live stack; custom probes **25 tests, 0 findings**; ZAP baseline pass (WARN only)

## Supply-chain audit (`cargo audit` / `cargo deny`)

**CI:** `.github/workflows/ci.yml` runs both on every push/PR.  
**Pre-deploy:** `./docker/run-supply-chain.sh`

### `cargo audit` (2026-07-05, after fixes)

```
Scanning Cargo.lock for vulnerabilities (450 crate dependencies)
```

Fixed in this round:

| Advisory | Action |
|----------|--------|
| RUSTSEC-2026-0185 (`quinn-proto` 0.11.14) | Pinned `quinn-proto = 0.11.15` in `Cargo.toml` |
| RUSTSEC-2025-0136 (`sequoia-openpgp` 1.x aes unwrap) | Upgraded to `sequoia-openpgp 2.1` (resolved 2.4.0) |

Documented/ignored (no upstream fix or not applicable):

| Advisory | Reason |
|----------|--------|
| RUSTSEC-2023-0071 (`rsa` Marvin timing) | **Reachability traced** — `rsa` via sequoia-openpgp only; Fulla uses `verify_backend` (public RSA verify), not private-key decrypt/sign (see below) |
| RUSTSEC-2025-0134 (`rustls-pemfile` unmaintained) | Transitive TLS stack; tracked upstream |
| RUSTSEC-2026-0190 (`anyhow` downcast_mut unsound) | Fulla does not use `Error::downcast_mut()` |

CI/harness command:

```bash
cargo audit --deny warnings \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2025-0134 \
  --ignore RUSTSEC-2026-0190
```

Exit code **0** when run in this environment after the above.

### `cargo deny check` (2026-07-05)

Config: `deny.toml` (licenses, advisories, sources).

```
advisories ok, bans ok, licenses ok, sources ok
```

Exit code **0**.

### HTTP stack fingerprinting

Reviewed error paths in `handlers/{submit,confirm,revoke,web}.rs`: client-facing 5xx and JSON errors use generic strings (`Internal error.`, `Not found.`) without crate names or version strings. Detailed errors go to `tracing::error!` server-side only. Startup `load_extension` failures are not exposed on HTTP.

## RUSTSEC-2023-0071 (`rsa` Marvin) — reachability analysis (2026-07-05)

### Dependency chain

```
cargo tree -i rsa
rsa v0.9.10
└── sequoia-openpgp v2.4.0
    └── fulla v0.1.0
```

The `rsa` crate is **not** in the rustls, lettre, sqlx, axum, or reqwest dependency trees (`cargo tree -i rsa --target all` shows sequoia-openpgp only). Optional TLS uses rustls (ring / aws-lc-rs), not the RustCrypto `rsa` crate.

### What Marvin affects

[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071): non-constant-time RSA **private-key** operations (`decrypt`, `sign`) — network-observable timing can leak **the private key performing the operation**.

### Fulla paths on attacker-submitted material

| Path | OpenPGP / RSA work | Private key on server? |
|------|-------------------|------------------------|
| `POST /api/v1/keys` → `openpgp::parse_and_validate` | `Cert::from_bytes`; `policy_check_keys` → `check_public_mpis` (RSA ≥2048 bit check only); `deny_self_revoked` → `StandardPolicy::revocation_status` | No — verifies signatures on **submitter's public cert** |
| `POST /api/v1/keys/revoke` → `apply_and_verify_revocation` | `merge_public`, `revocation_status` | No — verifies revocation signatures |
| `GET /keys` search | sqlx parameterized queries | No OpenPGP |

**`grep` across `src/`:** no `SecretParts`, `into_keypair`, `parts_into_secret`, `sign_backend`, or `decrypt_backend`. The only `into_keypair` in the repo is `adversarial-tests/src/poison_cert.rs` (test fixture builder, not server code).

In sequoia-openpgp 2.4.0 `crypto/backend/rust/asymmetric.rs`:
- Marvin-relevant: `sign_backend` (`RsaPrivateKey.sign`, ~line 680), `decrypt_backend` (`RsaPrivateKey.decrypt`, ~line 793) — require `SecretKeyMaterial`.
- What Fulla triggers via policy/revocation checks: `verify_backend` (`RsaPublicKey.verify`, ~lines 871–889) — **public** signature verification only.

Fulla stores armored **public** keys and never performs RSA decryption of attacker ciphertext with a server-held private key. Accepting RSA ≥2048-bit public keys is a Galdralag hardware policy choice in `policy_check_keys`; it does not introduce a Marvin oracle because verification uses the submitter's public `(n, e)`, not Fulla's private key.

### Conclusion

**`deny.toml` / audit ignore is justified.** No Fulla production path performs timing-sensitive RSA private-key operations via the `rsa` crate. Disabling RSA in `policy_check_keys` would be a product policy change, not a Marvin mitigation.

## Industry-standard scanners (executed 2026-07-05)

Stack: Podman, image `localhost/docker_fulla:latest`, endpoint `http://127.0.0.1:8080`.

| Tool | Command / image | Result |
|------|-----------------|--------|
| **trivy** | `podman run … aquasec/trivy:latest image localhost/docker_fulla:latest` (Podman socket mounted) | **0 HIGH/CRITICAL** (Debian 12.14, 106 packages) |
| **nikto** | `ghcr.io/sullo/nikto:latest` | 8 informational findings (missing headers; false-positive MLdonkey on fuzzed `/submit` query) |
| **sqlmap** | `sqlmap 1.10.7` (pip), `./docker/run-sqlmap-params.sh` | **0 injection** on all 9 GET `/keys` params |
| **nuclei** | `docker.io/projectdiscovery/nuclei:latest` | No high/critical output |
| **ZAP baseline** | `docker.io/zaproxy/zap-stable` | `FAIL-NEW: 0`, `WARN-NEW: 8` |

### trivy (full output)

Log: `docker/scanner-output/trivy-full.txt`

```
2026-07-04T23:54:53Z	INFO	[vuln] Vulnerability scanning is enabled
2026-07-04T23:54:53Z	INFO	[secret] Secret scanning is enabled
2026-07-04T23:54:54Z	INFO	Detected OS	family="debian" version="12.14"
2026-07-04T23:54:54Z	INFO	[debian] Detecting vulnerabilities...	os_version="12" pkg_num=106
2026-07-04T23:54:54Z	INFO	Number of language-specific files	num=0
2026-07-04T23:54:54Z	WARN	Using severities from other vendors for some vulnerabilities. Read https://trivy.dev/docs/v0.72/guide/scanner/vulnerability#severity-selection for details.

Report Summary

┌──────────────────────────────────────────────┬────────┬─────────────────┬─────────┐
│                    Target                    │  Type  │ Vulnerabilities │ Secrets │
├──────────────────────────────────────────────┼────────┼─────────────────┼─────────┤
│ localhost/docker_fulla:latest (debian 12.14) │ debian │        0        │    -    │
└──────────────────────────────────────────────┴────────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)
```

Exit code **0**. No HIGH/CRITICAL findings.

### nikto (full output)

Log: `docker/scanner-output/nikto-full.txt`

```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    127.0.0.1
+ Target Port:        8080
+ Start Time:         2026-07-04 23:55:26 (GMT0)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
+ /: Suggested security header missing: strict-transport-security. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ /: Suggested security header missing: x-content-type-options. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
+ /: Suggested security header missing: permissions-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
+ /: Suggested security header missing: referrer-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
+ OPTIONS: Allowed HTTP Methods: GET, HEAD .
+ /submit?setoption=q&option=allowed_ips&value=255.255.255.255: MLdonkey 2.x allows administrative interface access to be access from any IP. This is typically only found on port 4080. See: OSVDB-3126
+ 8084 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2026-07-04 23:55:31 (GMT0) (5 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Exit code **0**. No exploit-class findings; header hardening opportunities only.

**Note:** `docker.io/sullo/nikto:latest` pull denied on Docker Hub; scan used **`ghcr.io/sullo/nikto:latest`**.

### sqlmap — per GET `/keys` query parameter (full output)

Script: `./docker/run-sqlmap-params.sh` (also called from `run-scanners.sh` when `sqlmap` is on PATH).

**Scan config:** `KEYSERVER_RATE_LIMIT_READS=0` on the Docker stack during the clean run (avoids 429 from read rate limit during ~80 probes/param). Harness default remains `500` for adversarial probes.

**Result summary:** all nine parameters — `email`, `fingerprint`, `callsign`, `dmr_id`, `discord_id`, `irc_id`, `fluxer_id`, `first_name`, `last_name` — ended with `[WARNING] GET parameter '…' does not seem to be injectable` and `[ERROR] all tested parameters do not appear to be injectable`. No `is vulnerable` lines.

Logs: `docker/scanner-output/sqlmap-clean/<param>.txt` (53 lines each). Full verbatim output for all nine parameters:

#### `email` (full verbatim log)

```
=== sqlmap param=email url=http://127.0.0.1:8080/keys?email=test@example.com ===
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.7#pip}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:40 /2026-07-05/

[1/1] URL:
GET http://127.0.0.1:8080/keys?email=test@example.com
do you want to test this URL? [Y/n/q]
> Y
[01:56:40] [INFO] testing URL 'http://127.0.0.1:8080/keys?email=test@example.com'
[01:56:40] [INFO] flushing session file
[01:56:40] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:40] [INFO] testing connection to the target URL
[01:56:40] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:40] [INFO] testing if the target URL content is stable
[01:56:40] [INFO] target URL content is stable
[01:56:40] [INFO] testing if GET parameter 'email' is dynamic
[01:56:40] [WARNING] GET parameter 'email' does not appear to be dynamic
[01:56:40] [WARNING] heuristic (basic) test shows that GET parameter 'email' might not be injectable
[01:56:40] [INFO] heuristic (XSS) test shows that GET parameter 'email' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:40] [INFO] testing for SQL injection on GET parameter 'email'
[01:56:41] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:41] [WARNING] reflective value(s) found and filtering out
[01:56:41] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:41] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:41] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:41] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:41] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:41] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:41] [INFO] testing 'Generic inline queries'
[01:56:41] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:41] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:41] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:41] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:41] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:41] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:41] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:41] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:41] [WARNING] GET parameter 'email' does not seem to be injectable
[01:56:41] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:41] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:41 /2026-07-05/

exit: 0
```

#### `fingerprint` (full verbatim log)

```
=== sqlmap param=fingerprint url=http://127.0.0.1:8080/keys?fingerprint=ABCDEF0123456789ABCDEF0123456789ABCDEF01 ===
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10.7#pip}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:42 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?fingerprint=ABCDEF0123456789ABCDEF0123456789ABCDEF01
do you want to test this URL? [Y/n/q]
> Y
[01:56:42] [INFO] testing URL 'http://127.0.0.1:8080/keys?fingerprint=ABCDEF0123456789ABCDEF0123456789ABCDEF01'
[01:56:42] [INFO] flushing session file
[01:56:42] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:42] [INFO] testing connection to the target URL
[01:56:42] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:42] [INFO] testing if the target URL content is stable
[01:56:42] [INFO] target URL content is stable
[01:56:42] [INFO] testing if GET parameter 'fingerprint' is dynamic
[01:56:42] [WARNING] GET parameter 'fingerprint' does not appear to be dynamic
[01:56:42] [WARNING] heuristic (basic) test shows that GET parameter 'fingerprint' might not be injectable
[01:56:42] [INFO] heuristic (XSS) test shows that GET parameter 'fingerprint' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:43] [INFO] testing for SQL injection on GET parameter 'fingerprint'
[01:56:43] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:43] [WARNING] reflective value(s) found and filtering out
[01:56:43] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:43] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:43] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:43] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:43] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:43] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:43] [INFO] testing 'Generic inline queries'
[01:56:43] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:43] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:43] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:43] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:43] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:43] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:43] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:43] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:43] [WARNING] GET parameter 'fingerprint' does not seem to be injectable
[01:56:43] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:43] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:43 /2026-07-05/

exit: 0
```

#### `callsign` (full verbatim log)

```
=== sqlmap param=callsign url=http://127.0.0.1:8080/keys?callsign=TEST ===
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.7#pip}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:44 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?callsign=TEST
do you want to test this URL? [Y/n/q]
> Y
[01:56:44] [INFO] testing URL 'http://127.0.0.1:8080/keys?callsign=TEST'
[01:56:44] [INFO] flushing session file
[01:56:44] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:44] [INFO] testing connection to the target URL
[01:56:44] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:44] [INFO] testing if the target URL content is stable
[01:56:44] [INFO] target URL content is stable
[01:56:44] [INFO] testing if GET parameter 'callsign' is dynamic
[01:56:44] [WARNING] GET parameter 'callsign' does not appear to be dynamic
[01:56:44] [WARNING] heuristic (basic) test shows that GET parameter 'callsign' might not be injectable
[01:56:44] [INFO] heuristic (XSS) test shows that GET parameter 'callsign' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:44] [INFO] testing for SQL injection on GET parameter 'callsign'
[01:56:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:45] [WARNING] reflective value(s) found and filtering out
[01:56:45] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:45] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:45] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:45] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:45] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:45] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:45] [INFO] testing 'Generic inline queries'
[01:56:45] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:45] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:45] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:45] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:45] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:45] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:45] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:45] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:45] [WARNING] GET parameter 'callsign' does not seem to be injectable
[01:56:45] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:45] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:45 /2026-07-05/

exit: 0
```

#### `dmr_id` (full verbatim log)

```
=== sqlmap param=dmr_id url=http://127.0.0.1:8080/keys?dmr_id=12345 ===
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.7#pip}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:46 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?dmr_id=12345
do you want to test this URL? [Y/n/q]
> Y
[01:56:46] [INFO] testing URL 'http://127.0.0.1:8080/keys?dmr_id=12345'
[01:56:46] [INFO] flushing session file
[01:56:46] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:46] [INFO] testing connection to the target URL
[01:56:46] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:46] [INFO] testing if the target URL content is stable
[01:56:46] [INFO] target URL content is stable
[01:56:46] [INFO] testing if GET parameter 'dmr_id' is dynamic
[01:56:46] [WARNING] GET parameter 'dmr_id' does not appear to be dynamic
[01:56:46] [WARNING] heuristic (basic) test shows that GET parameter 'dmr_id' might not be injectable
[01:56:46] [INFO] testing for SQL injection on GET parameter 'dmr_id'
[01:56:46] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:46] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:46] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:46] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:47] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:47] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:47] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:47] [INFO] testing 'Generic inline queries'
[01:56:47] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:47] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:47] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:47] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:47] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:47] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:47] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:47] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:47] [WARNING] GET parameter 'dmr_id' does not seem to be injectable
[01:56:47] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:47] [WARNING] HTTP error codes detected during run:
400 (Bad Request) - 77 times
[01:56:47] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:47 /2026-07-05/

exit: 0
```

#### `discord_id` (full verbatim log)

```
=== sqlmap param=discord_id url=http://127.0.0.1:8080/keys?discord_id=test123 ===
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.7#pip}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:48 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?discord_id=test123
do you want to test this URL? [Y/n/q]
> Y
[01:56:48] [INFO] testing URL 'http://127.0.0.1:8080/keys?discord_id=test123'
[01:56:48] [INFO] flushing session file
[01:56:48] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:48] [INFO] testing connection to the target URL
[01:56:48] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:48] [INFO] testing if the target URL content is stable
[01:56:48] [INFO] target URL content is stable
[01:56:48] [INFO] testing if GET parameter 'discord_id' is dynamic
[01:56:48] [WARNING] GET parameter 'discord_id' does not appear to be dynamic
[01:56:48] [WARNING] heuristic (basic) test shows that GET parameter 'discord_id' might not be injectable
[01:56:48] [INFO] heuristic (XSS) test shows that GET parameter 'discord_id' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:48] [INFO] testing for SQL injection on GET parameter 'discord_id'
[01:56:48] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:48] [WARNING] reflective value(s) found and filtering out
[01:56:48] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:48] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:48] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:48] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:48] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:48] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:48] [INFO] testing 'Generic inline queries'
[01:56:48] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:48] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:48] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:48] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:48] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:48] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:49] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:49] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:49] [WARNING] GET parameter 'discord_id' does not seem to be injectable
[01:56:49] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:49] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:49 /2026-07-05/

exit: 0
```

#### `irc_id` (full verbatim log)

```
=== sqlmap param=irc_id url=http://127.0.0.1:8080/keys?irc_id=testnick ===
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.7#pip}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:50 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?irc_id=testnick
do you want to test this URL? [Y/n/q]
> Y
[01:56:50] [INFO] testing URL 'http://127.0.0.1:8080/keys?irc_id=testnick'
[01:56:50] [INFO] flushing session file
[01:56:50] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:50] [INFO] testing connection to the target URL
[01:56:50] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:50] [INFO] testing if the target URL content is stable
[01:56:50] [INFO] target URL content is stable
[01:56:50] [INFO] testing if GET parameter 'irc_id' is dynamic
[01:56:50] [WARNING] GET parameter 'irc_id' does not appear to be dynamic
[01:56:50] [WARNING] heuristic (basic) test shows that GET parameter 'irc_id' might not be injectable
[01:56:50] [INFO] heuristic (XSS) test shows that GET parameter 'irc_id' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:50] [INFO] testing for SQL injection on GET parameter 'irc_id'
[01:56:50] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:50] [WARNING] reflective value(s) found and filtering out
[01:56:50] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:50] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:50] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:50] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:50] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:50] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:50] [INFO] testing 'Generic inline queries'
[01:56:50] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:50] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:50] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:50] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:50] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:51] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:51] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:51] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:51] [WARNING] GET parameter 'irc_id' does not seem to be injectable
[01:56:51] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:51] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:51 /2026-07-05/

exit: 0
```

#### `fluxer_id` (full verbatim log)

```
=== sqlmap param=fluxer_id url=http://127.0.0.1:8080/keys?fluxer_id=fluxer1 ===
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10.7#pip}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:52 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?fluxer_id=fluxer1
do you want to test this URL? [Y/n/q]
> Y
[01:56:52] [INFO] testing URL 'http://127.0.0.1:8080/keys?fluxer_id=fluxer1'
[01:56:52] [INFO] flushing session file
[01:56:52] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:52] [INFO] testing connection to the target URL
[01:56:52] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:52] [INFO] testing if the target URL content is stable
[01:56:52] [INFO] target URL content is stable
[01:56:52] [INFO] testing if GET parameter 'fluxer_id' is dynamic
[01:56:52] [WARNING] GET parameter 'fluxer_id' does not appear to be dynamic
[01:56:52] [WARNING] heuristic (basic) test shows that GET parameter 'fluxer_id' might not be injectable
[01:56:52] [INFO] heuristic (XSS) test shows that GET parameter 'fluxer_id' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:52] [INFO] testing for SQL injection on GET parameter 'fluxer_id'
[01:56:52] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:52] [WARNING] reflective value(s) found and filtering out
[01:56:52] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:52] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:52] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:52] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:52] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:52] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:52] [INFO] testing 'Generic inline queries'
[01:56:52] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:53] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:53] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:53] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:53] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:53] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:53] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:53] [WARNING] GET parameter 'fluxer_id' does not seem to be injectable
[01:56:53] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:53] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:53 /2026-07-05/

exit: 0
```

#### `first_name` (full verbatim log)

```
=== sqlmap param=first_name url=http://127.0.0.1:8080/keys?first_name=Test ===
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.7#pip}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:54 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?first_name=Test
do you want to test this URL? [Y/n/q]
> Y
[01:56:54] [INFO] testing URL 'http://127.0.0.1:8080/keys?first_name=Test'
[01:56:54] [INFO] flushing session file
[01:56:54] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:54] [INFO] testing connection to the target URL
[01:56:54] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:54] [INFO] testing if the target URL content is stable
[01:56:54] [INFO] target URL content is stable
[01:56:54] [INFO] testing if GET parameter 'first_name' is dynamic
[01:56:54] [WARNING] GET parameter 'first_name' does not appear to be dynamic
[01:56:54] [WARNING] heuristic (basic) test shows that GET parameter 'first_name' might not be injectable
[01:56:54] [INFO] heuristic (XSS) test shows that GET parameter 'first_name' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:54] [INFO] testing for SQL injection on GET parameter 'first_name'
[01:56:54] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:54] [WARNING] reflective value(s) found and filtering out
[01:56:54] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:54] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:54] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:55] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:55] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:55] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:55] [INFO] testing 'Generic inline queries'
[01:56:55] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:55] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:55] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:55] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:55] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:55] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:55] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:55] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:55] [WARNING] GET parameter 'first_name' does not seem to be injectable
[01:56:55] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:55] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:55 /2026-07-05/

exit: 0
```

#### `last_name` (full verbatim log)

```
=== sqlmap param=last_name url=http://127.0.0.1:8080/keys?last_name=User ===
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10.7#pip}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:56:56 /2026-07-05/


[1/1] URL:
GET http://127.0.0.1:8080/keys?last_name=User
do you want to test this URL? [Y/n/q]
> Y
[01:56:56] [INFO] testing URL 'http://127.0.0.1:8080/keys?last_name=User'
[01:56:56] [INFO] flushing session file
[01:56:56] [INFO] using '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv' as the CSV results file in multiple targets mode
[01:56:56] [INFO] testing connection to the target URL
[01:56:56] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:56:56] [INFO] testing if the target URL content is stable
[01:56:56] [INFO] target URL content is stable
[01:56:56] [INFO] testing if GET parameter 'last_name' is dynamic
[01:56:56] [WARNING] GET parameter 'last_name' does not appear to be dynamic
[01:56:56] [WARNING] heuristic (basic) test shows that GET parameter 'last_name' might not be injectable
[01:56:57] [INFO] heuristic (XSS) test shows that GET parameter 'last_name' might be vulnerable to cross-site scripting (XSS) attacks
[01:56:57] [INFO] testing for SQL injection on GET parameter 'last_name'
[01:56:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:56:57] [WARNING] reflective value(s) found and filtering out
[01:56:57] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:56:57] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:56:57] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:56:57] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:56:57] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:56:57] [INFO] testing 'H2 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (CAST)'
[01:56:57] [INFO] testing 'Generic inline queries'
[01:56:57] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:56:57] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:56:57] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:56:57] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:56:57] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:56:57] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:56:57] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:56:57] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:56:57] [WARNING] GET parameter 'last_name' does not seem to be injectable
[01:56:57] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[01:56:57] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/haaken/.local/share/sqlmap/output/results-07052026_0156am.csv'

[*] ending @ 01:56:57 /2026-07-05/

exit: 0
```

**Note:** `docker.io/sqlmapproject/sqlmap:latest` pull denied; scan used **`sqlmap 1.10.7` via pip**. `docker.io/parrotsec/sqlmap:latest` pulls successfully as a container fallback in `run-scanners.sh`.

### OWASP ZAP baseline (prior run, same stack)

```
FAIL-NEW: 0	FAIL-INPROG: 0	WARN-NEW: 8	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 59
```

Blocking rule in `run-scanners.sh`: HIGH/CRITICAL from trivy/nuclei, sqlmap injection, ZAP FAIL with High/Critical.

## Spam resistance decision

**Chosen:** (b) **`KEYSERVER_RATE_LIMIT_SUBMISSIONS_GLOBAL` on-by-default at 300/hour** (`0` disables), plus (c) **document closed registry** as the real answer for high-risk deployments.

**Not chosen:** (a) proof-of-work — adds friction to Galdra handset push and web submit without replacing mailbox confirmation; open registry accessibility is a product requirement.

**Tension:** Per-IP limits fail against botnets/VPN rotation. Global cap limits total cluster spam but does not stop slow distributed abuse. **`KEYSERVER_MUTATION_AUTH_SECRET`** remains the recommended control when open registration spam is unacceptable.

## CR-SQLite extension integrity

Implemented in `src/extension_integrity.rs`: reject group/world-writable extension path; optional `crsqlite_extension_sha256` in `[replication.mesh]`. Unit tests: `extension_integrity::tests::*`.

## Environment

| Item | Value |
|------|--------|
| Host OS | Linux 6.17.0-35-generic (Ubuntu 24.04 base), x86_64 |
| Container runtime | Podman 4.9.3 via `DOCKER_HOST=unix:///run/user/1000/podman/podman.sock` |
| Fulla endpoint | `http://127.0.0.1:8080/` |
| MailHog | `http://127.0.0.1:8025/` |

### Harness configuration

| Setting | Value |
|---------|--------|
| `KEYSERVER_RATE_LIMIT_SUBMISSIONS` | 50 |
| `KEYSERVER_RATE_LIMIT_READS` | 500 |
| `KEYSERVER_RATE_LIMIT_SUBMISSIONS_GLOBAL` | 5000 (harness override; production default 300 when unset) |
| `KEYSERVER_SMTP_TLS` | false |
| `KEYSERVER_MUTATION_AUTH_SECRET` | unset (open registry in Docker env) |

## SKS poison fixture — which defense catches it

| Item | Value |
|------|--------|
| Fixture | `adversarial-tests/fixtures/sks_uid_selfsig_flood.asc` (40 PositiveCertification packets on one User ID) |
| Builder | `adversarial-tests/src/poison_cert.rs` — raw packet stream, bypasses `insert_packets` dedup |
| Adversarial probe | `sks_poison_uid_selfsig_flood` |
| Unit test | `openpgp::tests::strict_policy_rejects_sks_uid_selfsig_flood` |

**Defense that rejects the real attack shape:** `check_raw_packet_structure` in `src/openpgp.rs` — **per-UID self-signature cap on the import stream** (`KEYSERVER_MAX_UID_SELF_SIGNATURES`, default 32). Error text includes `self-signatures in import stream`.

**Why raw-stream check is required:** Sequoia’s `Cert::from_bytes` amalgamation deduplicates flooded binding signatures down to one per User ID. The post-amalgamation `check_cert_structure` / `uid.self_signatures().count()` path does **not** see the flood; the total signature-packet backstop (`max_uid_self_signatures × max_userids` = 512 by default) also does **not** fire at 40 packets.

## Executed results (2026-07-05)

| Category | Test | Result | Detail |
|----------|------|--------|--------|
| malformed | oversized_request_body | PASS | HTTP 413 Payload Too Large |
| malformed | bad_openpgp | PASS | HTTP 422 with reason |
| malformed | oversized_note_field | PASS | HTTP 422 |
| malformed | invalid_utf8_json | PASS | HTTP 400 Bad Request |
| malformed | fingerprint_path_short | PASS | HTTP 400 |
| malformed | fingerprint_path_non_hex | PASS | HTTP 400 |
| malformed | fingerprint_path_traversal | PASS | HTTP 404 |
| malformed | fingerprint_path_sqli | PASS | HTTP 400 |
| malformed | bloated_cert_excess_userids | PASS | HTTP 422 structural limit rejected |
| malformed | bloated_cert_excess_subkeys | PASS | HTTP 422 structural limit rejected |
| malformed | bloated_cert_excess_userids_and_subkeys | PASS | HTTP 422 structural limit rejected |
| malformed | sks_poison_uid_selfsig_flood | PASS | HTTP 422 — per-UID self-signature cap on raw import stream (check_raw_packet_structure) |
| identity | email_case_variant_pending_guard | PASS | User@Example.com blocked while user@example.com pending |
| identity | unicode_homoglyph_pending_guard | PASS | 422 pending guard blocks homoglyph mailbox |
| tokens | confirm_once | PASS | HTTP 200 |
| tokens | confirm_replay | PASS | second GET /confirm returns 404 |
| tokens | token_timing_side_channel | SKIP | sub-millisecond timing resolution; 256-bit token entropy |
| automated | json_fuzz_0–3 | PASS | HTTP 422 |
| automated | search_revoked_filter_gap | PASS | active-only multi-filter; include_revoked opt-in |
| automated | slow_partial_post | PASS | connection closed within timeout |
| rate_limit | mutate_per_ip_hourly | PASS | HTTP 429 at limit+2 |
| rate_limit | read_side_per_ip_hourly | PASS | HTTP 429 at limit+2 |

**Unit tests (`cargo test`):** 58 passed, 0 failed, 1 ignored (mesh two-node manual test). Includes extension integrity, mesh conflict local-confirm precedence, and supply-chain-adjacent OpenPGP upgrades (sequoia 2.x).

## Mesh email conflict resolution (`mesh_conflict`)

| Item | Detail |
|------|--------|
| Trust issue | Replicated `submitted_at` and grindable fingerprint are not valid trust boundaries for mesh-only attackers |
| Fix | **Locally confirmed on this node** beats replication-only; else earliest **`first_seen_at`** (local-only, not CR-SQLite) |
| Wire/schema change | **Local schema only** (`010_key_local_provenance.sql`); `keys` wire format unchanged. **Upgrade all mesh nodes together** for consistent resolver |
| Attacker cost (mesh inject only) | Cannot set `key_local_confirmations`; can only win replication-only tier by being observed first on that node — not by fingerprint grinding |
| Wrongly revoked owner | No automatic notification; re-submit + mailbox confirmation to supersede attacker |
| Tests | `fingerprint_tiebreak_is_gameable_*`, `local_confirm_beats_*`, `apply_crsql_wire_rows_cannot_inject_local_confirmation`, `resolve_keeps_locally_confirmed_*` |

Verified by `cargo test` (not Docker adversarial — mesh path).

## Mesh truncation-block (protocol v2)

| Condition | Behaviour |
|-----------|-----------|
| Pull batch `< sync_max_changes_per_request` from pre-v2 peer | Sync allowed (staged rollout OK) |
| Pull batch `>= sync_max_changes_per_request` from pre-v2 peer | **Fail closed** — `TruncationBlockedError`, batch not applied, `mesh_peers` cursor unchanged, `tracing::error!`, retry next cron |
| 3+ consecutive truncation-blocks for same peer | Escalated **upgrade-now** error log |

Verified by `replication::mesh::tests` (not covered by Docker adversarial harness).

## token_timing_side_channel — why SKIP (not PASS)

The probe is **not a silent no-op**. It performs 10 timed `GET /confirm/{wrong64hex}` and 10 timed `GET /reject/{wrong64hex}` requests and compares average durations.

On typical hardware the averages are **sub-millisecond**. SKIP means **measurement insufficient**, not **vulnerability found**.

## Resolved gaps

| Gap | Resolution |
|-----|----------------|
| Multi-filter search returns revoked keys | `KeyFilter.include_revoked`; default active-only for JSON |
| Unicode homoglyph pending bypass | `email_canonical` + `email_normalize.rs` |
| No read-side rate limit | `KEYSERVER_RATE_LIMIT_READS` |
| Unbounded mesh GET `/sync/changes` | Pagination + protocol v2; truncation fail-closed for old peers on full pages |
| Mesh conflict backdated `submitted_at` / fingerprint grinding | Local-confirm + first-seen precedence in `resolve_mesh_email_conflicts` |
| No SKS-style cert probes | Raw poison fixture + `check_raw_packet_structure` |
| No mutation-auth HTTP test | `main.rs` `http_integration_tests` module |

## Remaining / documented limits

| Item | Status |
|------|--------|
| Mesh mixed-version deployment | Staged rollout OK for small batches; full-page pulls from pre-v2 peers fail closed — see `docs/FULLA_INTEGRATION.md` |
| Token timing side channel | SKIP — harness resolution too coarse; 256-bit entropy |

## Reproduce

```bash
export DOCKER_HOST=unix:///run/user/1000/podman/podman.sock
systemctl --user start podman.socket
./docker/run-adversarial.sh
cargo test
```

Exit code **1** when any adversarial row is **FINDING**; **0** when all probes pass or only SKIP/KNOWN_GAP remain.
