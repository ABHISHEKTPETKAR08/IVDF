# IVDAF REST API Documentation

Base URL: `http://localhost:8000`  
Interactive docs: `http://localhost:8000/docs` (Swagger UI)  
OpenAPI spec: `http://localhost:8000/openapi.json`

---

## Authentication

No authentication is required in the default configuration.  
For production deployments, add an API key middleware and pass:

```
X-API-Key: your-api-key
```

---

## Endpoints

### Health

#### `GET /health`
```json
{ "status": "ok", "version": "1.0.0" }
```

---

### Targets

#### `GET /targets`
List all registered scan targets.

**Response 200:**
```json
[
  {
    "id": "uuid",
    "address": "192.168.1.100",
    "description": "DVWA instance",
    "resolved_ip": "192.168.1.100",
    "last_scanned_at": "2024-01-15T10:30:00"
  }
]
```

#### `POST /targets`
Register a new target.

**Request:**
```json
{ "address": "192.168.1.100", "description": "DVWA" }
```

**Response 201:**
```json
{ "id": "uuid", "address": "192.168.1.100", ... }
```

**Errors:**
- `422` — Target address fails private-IP validation
- `409` — Target already registered

#### `DELETE /targets/{target_id}`
Remove a target.

---

### Scans

#### `POST /scan`
Initiate a vulnerability scan.

**Request:**
```json
{
  "target": "192.168.1.100",
  "scan_type": "full",
  "port_range": "1-1024",
  "adaptive_mode": false,
  "description": "Optional description"
}
```

| Field | Type | Required | Values |
|-------|------|----------|--------|
| target | string | Yes | RFC 1918 IP or lab hostname |
| scan_type | string | No | `full` \| `quick` \| `stealth` (default: `full`) |
| port_range | string | No | `1-1024` or `80,443,8080` (default: `1-1024`) |
| adaptive_mode | boolean | No | Default: `false` |

**Response 202:**
```json
{
  "scan_id": "uuid",
  "target": "192.168.1.100",
  "status": "pending",
  "message": "Scan queued. Poll GET /scan/{scan_id} for status.",
  "task_id": "celery-task-uuid"
}
```

**Errors:**
- `422` — Validation failure (invalid target, port range, or scan type)

#### `GET /scan/{scan_id}`
Poll scan status.

**Response 200:**
```json
{
  "scan_id": "uuid",
  "target": "192.168.1.100",
  "status": "completed",
  "scan_type": "full",
  "port_range": "1-1024",
  "adaptive_mode": false,
  "started_at": "2024-01-15T10:30:00",
  "completed_at": "2024-01-15T10:32:30",
  "duration_seconds": 150.3,
  "vulnerability_count": 7,
  "error_message": null
}
```

**Status values:** `pending` → `running` → `completed` | `failed` | `cancelled`

#### `DELETE /scan/{scan_id}`
Cancel a pending scan.

---

### Results

#### `GET /results`
List scan results with pagination.

**Query parameters:**
- `page` (int, default 1)
- `per_page` (int, default 20, max 100)
- `status` (string, optional) — filter by status

**Response 200:**
```json
[
  {
    "scan_id": "uuid",
    "target": "192.168.1.100",
    "status": "completed",
    "scan_type": "full",
    "started_at": "...",
    "completed_at": "...",
    "vulnerability_count": 7,
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
  }
]
```

#### `GET /results/{scan_id}`
Full result set including all vulnerability findings.

---

### Vulnerabilities

#### `GET /vulnerabilities`
List all findings with filters.

**Query parameters:**
- `severity` — `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`
- `scan_id` — filter by specific scan
- `page`, `per_page`

#### `GET /vulnerabilities/{vuln_id}`
Full finding with enriched explanation.

**Response 200:**
```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "name": "SQL Injection",
  "vuln_type": "SQL Injection",
  "severity": "HIGH",
  "cvss_score": 8.8,
  "owasp_mapping": "A03:2021 – Injection",
  "cwe": "CWE-89",
  "summary": "The application accepts unsanitized SQL input.",
  "description": "SQL Injection occurs when user-controlled input...",
  "attack_scenario": "An attacker submits ' OR '1'='1 as a login username...",
  "impact": "Data breach, authentication bypass...",
  "fix": [
    "Use parameterised queries / prepared statements.",
    "Apply input validation and allowlist filtering.",
    ...
  ],
  "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
  "affected_url": "http://192.168.1.100/login?id=1'",
  "payload_used": "'",
  "cve_references": [],
  "is_false_positive": false
}
```

#### `PATCH /vulnerabilities/{vuln_id}/false-positive`
Toggle false-positive flag on a finding.

---

### Reports

#### `POST /reports/{scan_id}`
Generate a report for a completed scan.

**Request:**
```json
{ "format": "pdf" }
```

Formats: `pdf` | `json` | `csv`

**Response 201:**
```json
{
  "report_id": "uuid",
  "scan_id": "uuid",
  "format": "pdf",
  "file_path": "./reports/report_abc12345_20240115_103000.pdf",
  "file_size_bytes": 45312,
  "generated_at": "2024-01-15T10:35:00"
}
```

#### `GET /reports`
List all generated reports.

#### `GET /reports/{report_id}/download`
Download a report file. Returns binary with appropriate `Content-Type`.

---

## Error Response Format

All errors follow:
```json
{
  "detail": "Human-readable error message"
}
```

For validation errors (422):
```json
{
  "detail": [
    {
      "loc": ["body", "target"],
      "msg": "IP 8.8.8.8 is not in a private range...",
      "type": "value_error"
    }
  ]
}
```

---

## Rate Limiting

- **Limit:** 100 requests per 60 seconds per IP address
- **Headers:** `X-RateLimit-Limit`, `X-RateLimit-Remaining`
- **429 response:** Includes `Retry-After` header

---

## Sample cURL Commands

```bash
# Health check
curl http://localhost:8000/health

# Register a target
curl -X POST http://localhost:8000/targets \
  -H "Content-Type: application/json" \
  -d '{"address": "192.168.1.100", "description": "DVWA"}'

# Initiate a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100", "scan_type": "full", "port_range": "1-1024"}'

# Poll scan status
curl http://localhost:8000/scan/<scan_id>

# List findings
curl http://localhost:8000/vulnerabilities?severity=HIGH

# Generate PDF report
curl -X POST http://localhost:8000/reports/<scan_id> \
  -H "Content-Type: application/json" \
  -d '{"format": "pdf"}'

# Download report
curl -O http://localhost:8000/reports/<report_id>/download
```
