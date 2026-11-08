# Report Privacy, Sanitization & Redaction Controls

To comply with data privacy regulations (GDPR, HIPAA) and corporate security policies, `systemscan` includes configurable privacy redaction controls via the `--redact` flag.

---

## 1. Redaction Policies & Data Categories

| Category | Regex / Target | Original Example | Redacted Replacement |
| :--- | :--- | :--- | :--- |
| **User Paths** | `/home/<user>`, `C:\Users\<user>` | `/home/johndoe/projects` | `/home/[USER]/projects` |
| **Usernames** | Account identifiers | `johndoe` | `[USER]` |
| **Hostnames** | Host / machine names | `sec-corp-laptop-42` | `[REDACTED_HOST]` |
| **Private IPs** | RFC 1918 IPv4 ranges | `192.168.1.150` | `[PRIVATE_IP]` |
| **MAC Addresses**| Hardware adapter MACs | `00:1A:2B:3C:4D:5E` | `XX:XX:XX:XX:XX:5E` |
| **Serials** | BIOS / hardware serial numbers | `SN: 8A29F41920B` | `SN: [REDACTED_SERIAL]` |
| **Secrets** | Passwords, tokens, bearer keys | `token=eyJhbGciOi...` | `token=[REDACTED_SECRET]` |

---

## 2. Immutability Guarantee

`ReportRedactor` **never mutates original scan records or in-memory scan history**.

- Redaction operates exclusively on an isolated deep copy (`copy.deepcopy(report)`).
- The resulting report sets `metadata.is_redacted = True` and records the exact list of applied policies in `metadata.redaction_policy`.
- Internal telemetry, threat hashes, and audit ledgers retain their original evidentiary integrity for forensic review.

---

## 3. Usage Examples

```bash
# Generate sanitized JSON report for external compliance sharing
systemscan report generate --scan-id scan-001 --format json --redact

# Export sanitized text summary
systemscan report export --scan-id scan-001 --format txt --redact --output /tmp/clean_report.txt
```

