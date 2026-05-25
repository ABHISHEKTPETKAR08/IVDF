# Security Checklist for Production Deployment

> **BEFORE pushing to GitHub or deploying to production, complete ALL items marked `CRITICAL`**

---

## 🔴 CRITICAL SECURITY ITEMS

### Secrets & Credentials

- [ ] **SECRET_KEY is NOT the placeholder `CHANGE-ME`**
  - Generate: `python -c "import secrets; print(secrets.token_hex(32))"`
  - Minimum 32 characters
  - Never commit to `.env`

- [ ] **Database credentials are NOT defaults (`scanner:scanner`)**
  - PostgreSQL password: Generate strong random (32+ chars)
  - Username changed from default `scanner`
  - Stored ONLY in `.env` (NOT committed)

- [ ] **Flower credentials are NOT `admin:admin`**
  - Generate: `python -c "import secrets; print(secrets.token_urlsafe(16))"`
  - Stored ONLY in `.env` (NOT committed)

- [ ] **Redis has authentication enabled in production**
  - REDIS_URL includes password: `redis://:PASSWORD@host:6379/0`
  - Not using default `redis://localhost:6379/0` in production

- [ ] **`.env` file is NEVER committed to Git**
  - Confirm: `.env` is in `.gitignore`
  - Remove if accidentally committed: `git rm --cached .env && git commit -m "Remove .env"`
  - Only `.env.example` with placeholders is committed

### Git & Source Code

- [ ] **No hardcoded secrets in source code**
  - Run: `grep -r "password\|secret\|key\|token\|CHANGE-ME" backend/ --include="*.py"`
  - All security configs must be environment variables

- [ ] **No API keys, webhooks, or tokens in comments**
  - Search for: `# key=`, `# secret=`, `# token=`

- [ ] **No database migrations with real credentials**
  - Check: `backend/database/migrations/` (if exists)
  - Credentials in migrations must use env vars

- [ ] **Git history cleaned of sensitive data**
  - If secrets were committed:
    - Use `git-filter-branch` to remove from history
    - OR force push after cleanup (requires repo reset)
    - Notify team to re-clone

### Database Security

- [ ] **PostgreSQL binding is NOT exposed to public interfaces**
  - Check docker-compose.yml line 38: Must be `127.0.0.1:5432:5432` (not `0.0.0.0:5432`)
  - In production: Use managed database (RDS, Azure Database) NOT self-hosted

- [ ] **Database URL does NOT contain credentials in code**
  - Load from `DATABASE_URL` env var
  - Sanitize if logged: `postgresql://***@host/db`

- [ ] **Database backups are encrypted**
  - Production requirement: Enable automated backups
  - Enable encryption at rest

### API Security

- [ ] **CORS is NOT set to wildcard (`*`)**
  - Allowed: `http://localhost:8501,https://your-frontend.com`
  - NOT: `*` or `http://*`

- [ ] **Rate limiting is enabled**
  - RATE_LIMIT_REQUESTS=100
  - RATE_LIMIT_PERIOD=60
  - Should be stricter in production (consider 50/60)

- [ ] **HTTPS/TLS is enforced in production**
  - Frontend must be HTTPS
  - Backend must be HTTPS (via reverse proxy)
  - Redirect HTTP → HTTPS

- [ ] **Security headers are present**
  - Verify in browser: `curl -I https://your-api.domain.com`
  - Check for: `X-Content-Type-Options: nosniff`
  - Check for: `X-Frame-Options: DENY`
  - Check for: `Strict-Transport-Security`

### Logging & Monitoring

- [ ] **Sensitive data is NOT logged**
  - Sanitize before logging: passwords, tokens, keys
  - Check `backend/utils/logger.py`
  - Verify: DATABASE_URL with credentials is NOT logged
  - Verify: SECRET_KEY is NOT logged

- [ ] **Error messages don't expose system details**
  - Production: Generic error messages
  - Development: Detailed error messages OK
  - Confirm `DEBUG=false` in production `.env`

- [ ] **Logs are retained securely**
  - Logs stored with restricted permissions (600)
  - Logs not readable by unprivileged users
  - Logs rotated/archived (not infinite size)

---

## 🟠 HIGH PRIORITY SECURITY ITEMS

### Docker & Deployment

- [ ] **Docker images don't contain secrets**
  - No `.env` files in `docker-compose.yml`
  - No hardcoded passwords in `Dockerfile`
  - Use build args and secret mounting

- [ ] **Docker layers are optimized**
  - `RUN pip install` commands don't expose credentials
  - Multi-stage builds for minimal final image

- [ ] **Container runs as non-root user**
  - Check `Dockerfile`: `USER scanner` or similar
  - Prevents privilege escalation

### Dependencies

- [ ] **No vulnerable dependencies**
  - Run: `pip check` to check for conflicts
  - Run: `pip-audit` or `safety check` for CVEs
  - Update: `pip install --upgrade pip`

- [ ] **Dependency versions are locked**
  - Use: `pip freeze > requirements-locked.txt` for production
  - Don't use: `>=`, `>`, `~=` without caps

### Monitoring & Alerts

- [ ] **Health checks are implemented**
  - `/health` endpoint returning 200
  - `/health/full` endpoint for deep checks
  - Configured in deployment platform

- [ ] **Monitoring alerts configured**
  - High error rates trigger alerts
  - Database connection failures trigger alerts
  - Memory/CPU warnings configured

---

## 🟡 MEDIUM PRIORITY SECURITY ITEMS

### API Validation

- [ ] **All user inputs are validated**
  - IP addresses must be RFC 1918 private ranges
  - Port ranges must be within 1-65535
  - Scan types must be from allowed list

- [ ] **SQL injection prevention**
  - Using SQLAlchemy ORM (not raw SQL)
  - All queries use parameterized statements
  - No string interpolation in queries

- [ ] **XSS prevention in frontend**
  - Streamlit auto-escapes by default ✅
  - User input not rendered as HTML

### Access Control

- [ ] **API key/authentication requirements reviewed**
  - Public endpoints listed
  - Protected endpoints require auth (if needed)
  - Rate limiting applies to all endpoints

### Documentation

- [ ] **Security documentation updated**
  - README.md includes security notice
  - `SECURITY.md` file created for vulnerability reporting
  - Deployment guide includes security section

---

## 🟢 LOW PRIORITY SECURITY ITEMS

### Code Quality

- [ ] **Security-focused code review completed**
  - Any code using subprocess reviewed (nmap integration)
  - File operations reviewed for path traversal
  - External API calls reviewed for SSRF

- [ ] **Comments don't reveal sensitive information**
  - TODO comments don't expose secrets
  - No debug/test credentials in comments

### Maintenance

- [ ] **Security patch process documented**
  - How to respond to vulnerability reports
  - How to apply security updates
  - Rollback procedure documented

---

## GitHub Preparation Checklist

Before pushing to GitHub:

- [ ] All `.env` files removed from repo
- [ ] `.gitignore` properly configured
- [ ] No secrets in Git history
- [ ] `SECURITY.md` file created
- [ ] `LICENSE` file present (MIT recommended)
- [ ] `README.md` includes security disclaimers
- [ ] Contributing guidelines created
- [ ] Code of Conduct added
- [ ] No API keys in documentation
- [ ] No internal IP addresses in documentation

---

## Production Deployment Checklist

Before deploying to production:

- [ ] All CRITICAL items completed
- [ ] All HIGH items completed
- [ ] Secrets Manager/Vault configured (e.g., AWS Secrets Manager)
- [ ] Database has automated backups enabled
- [ ] SSL/TLS certificates installed (not self-signed)
- [ ] Firewall rules configured (only expose 443)
- [ ] DDoS protection enabled (CloudFlare, AWS Shield)
- [ ] Monitoring and alerting active
- [ ] Incident response plan documented
- [ ] Team trained on security procedures

---

## Command Reference

### Generate Random Secrets

```bash
# 32-character hex SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# 32-character URL-safe password
python -c "import secrets; print(secrets.token_urlsafe(32))"

# 16-character Flower password
python -c "import secrets; print(secrets.token_urlsafe(16))"
```

### Check for Secrets in Code

```bash
# Find common patterns
grep -r "CHANGE-ME\|password\|secret\|api.key\|token" backend/ --include="*.py"

# Find in .env files
grep -E "^[A-Z_]+=.*(secret|password|key|token)" .env*
```

### Remove Accidentally Committed .env

```bash
# Remove from Git (but keep locally)
git rm --cached .env

# Commit the removal
git commit -m "Remove .env with credentials from repository"

# Push to remote
git push
```

### Verify No Secrets in Current Code

```bash
# After cleanup, verify
git log --all --full-history -- .env
# Should return empty or only removal commits
```

---

## Security Escalation Path

If a security vulnerability is discovered:

1. **DO NOT commit vulnerability details to public repo**
2. **Contact security team via SECURITY.md**
3. **Create private security advisory**
4. **Patch and deploy to production immediately**
5. **Notify users if data affected**
6. **Public disclosure after patch is live (90 days)**

---

## Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Secure coding guidelines: https://cheatsheetseries.owasp.org/
- Secrets management: https://12factor.net/config
- Security headers: https://securityheaders.com/

---

**Last Updated:** 2026-05-24  
**Status:** Review before production deployment  
**Owner:** Security Team
