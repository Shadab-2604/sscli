# Supported Report Export Formats

`systemscan` provides three standardized export formats designed for direct consumption by humans, spreadsheets, security information management systems (SIEMs), and data pipelines.

---

## 1. JSON Export (`--format json`)

- **Format Standard**: Strict UTF-8 encoded JSON.
- **Timestamp Standard**: ISO 8601 with UTC timezone offsets (`YYYY-MM-DDTHH:MM:SSZ`).
- **Validation Guarantee**: Every JSON export is validated upon generation and can be reloaded and verified using `JSONReportExporter.load_from_file()`.
- **Use Cases**: Ingestion by Elasticsearch, Splunk, automated CI/CD security quality gates, and API workflows.

---

## 2. CSV Export (`--format csv`)

`systemscan` supports both single-file findings exports and full multi-table CSV bundles.

### Findings CSV Headers:
```csv
finding_id,scan_id,title,category,severity,confidence,target,detected_at,source_module,description,evidence,remediation
```

### Summary CSV Headers:
```csv
report_id,scan_id,scan_type,status,system_identifier,os_description,start_time,completion_time,duration_seconds,items_analyzed,data_processed_bytes,items_skipped,errors_count,critical_findings,high_findings,medium_findings,low_findings,info_findings,total_findings,overall_result,completeness_percent
```

### Errors CSV Headers:
```csv
error_id,scan_id,timestamp,source_module,error_type,message,target
```

- **Encoding**: UTF-8 with BOM (`utf-8-sig`) ensuring seamless compatibility with Microsoft Excel, LibreOffice Calc, and Google Sheets across Windows, macOS, and Linux.
- **Escaping**: Strict RFC 4180 escaping for commas, quotes, line breaks, and Unicode filenames.

---

## 3. Plain Text Export (`--format txt`)

Supports three template presentation styles:

### A. Technical Report (`--style technical`)
- Default exhaustive format containing all collected evidence.
- Contains executive summary, system environment, operational telemetry, findings breakdown with complete evidence strings, errors, and disclaimers.

### B. Executive Summary (`--style executive`)
- Condensed 1–2 page management brief emphasizing severity totals, overall posture verdict, critical observations, and prioritized recommendations.

### C. Compact Terminal (`--style compact`)
- Space-efficient, single-screen output designed for automated logs, cron emails, or shell pipe inspection.

