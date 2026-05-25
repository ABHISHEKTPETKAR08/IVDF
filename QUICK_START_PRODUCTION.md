# 🚀 QUICK REFERENCE: Commands to Get Production Ready

## Copy-Paste Ready Commands

### 1️⃣ GENERATE NEW SECRETS

```bash
# Generate SECRET_KEY (32-char random)
python -c "import secrets; print(secrets.token_hex(32))"

# Generate POSTGRES_PASSWORD (32-char random)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate FLOWER_PASSWORD (16-char random)
python -c "import secrets; print(secrets.token_urlsafe(16))"

# Generate REDIS_PASSWORD (16-char random)
python -c "import secrets; print(secrets.token_urlsafe(16))"
```

**OUTPUT:** Copy these values and save securely (not in Git!)

---

### 2️⃣ FIX .ENV AND GIT

```bash
# Remove .env from Git (CRITICAL - do this first!)
git rm --cached .env

# Commit the removal
git commit -m "Remove .env with credentials from repository"

# Verify removal
git log --all --full-history -- .env

# Push to clean Git history
git push
```

---

### 3️⃣ UPDATE .ENV FILE (LOCAL ONLY - DON'T COMMIT)

```bash
# Create local .env (DO NOT add to Git)
cat > .env << 'EOF'
# Backend Settings
DEBUG=false
SECRET_KEY=<PASTE-YOUR-SECRET-KEY-HERE>
API_BASE_URL=http://localhost:8000

# Database (SQLite for dev, PostgreSQL for prod)
DATABASE_URL=sqlite+aiosqlite:///./vuln_scanner.db

# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# Celery (optional)
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2

# Frontend
FRONTEND_URL=http://localhost:8501

# Scanning
SCAN_TIMEOUT=30
SCAN_PORTS=80,443,8000,8501

# CORS
CORS_ORIGINS=http://localhost:8501,http://127.0.0.1:8501

# Nmap
NMAP_ENABLED=true
NMAP_PATH=/usr/bin/nmap

# Logging
LOG_LEVEL=INFO

# Security
FLOWER_USERNAME=admin
FLOWER_PASSWORD=<PASTE-YOUR-FLOWER-PASSWORD-HERE>
POSTGRES_PASSWORD=<PASTE-YOUR-POSTGRES-PASSWORD-HERE>
EOF
```

**⚠️ IMPORTANT:** This .env is local only - never commit to Git!

---

### 4️⃣ VERIFY NO SECRETS IN GIT

```bash
# Check for common secret patterns
git log -p | grep -i "password\|secret\|key\|token\|credential" | head -20

# Check current files for hardcoded secrets
grep -r "CHANGE-ME" backend/ || echo "✅ No CHANGE-ME found"
grep -r "scanner:scanner" . --include="*.py" --include="*.yml" || echo "✅ No weak passwords found"

# Detailed search
grep -r "SECRET_KEY\|POSTGRES_PASSWORD\|FLOWER_PASSWORD" . --include="*.py" --include="*.env" | grep -v "\.env\.example"
```

---

### 5️⃣ VALIDATE LOCAL SETUP

```bash
# Test backend starts without errors
python -m backend.app

# Expected output (no SECURITY WARNING):
# ✅ "Database initialised"
# ✅ "Application startup complete"
# ❌ NOT "SECURITY WARNING: SECRET_KEY is default"
```

**Stop with Ctrl+C after seeing startup messages**

---

### 6️⃣ TEST HEALTH ENDPOINTS

```bash
# Test basic health
curl http://localhost:8000/health

# Should return: {"status":"ok","version":"1.0.0"}

# Test detailed health
curl http://localhost:8000/health/full

# Should show: database, redis, celery status
```

---

### 7️⃣ SCAN FOR SECRETS IN REPO

```bash
# Install detect-secrets (optional, for thorough scanning)
pip install detect-secrets

# Scan repository
detect-secrets scan --baseline .secrets.baseline

# View results
detect-secrets list
```

---

### 8️⃣ PREPARE FOR GITHUB

```bash
# Create .gitignore (if not exists)
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*.egg-info/
.pytest_cache/
.coverage
htmlcov/
.venv/
venv/

# Environment
.env
.env.*
!.env.example

# Data
*.db
*.sqlite
*.sqlite3
scan-results/
reports/
exports/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs
logs/
*.log

# Docker
docker-data/
tmp/
EOF

# Verify .gitignore is correct
git status
```

---

### 9️⃣ CREATE GITHUB REPOSITORY

```bash
# Initialize (if not already)
git init
git add .
git commit -m "Initial commit: Production-ready IVDAF"

# Create GitHub repo first via web browser, then:
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/project-name.git
git push -u origin main
```

---

### 🔟 SECURITY CHECKLIST

```bash
# Run before any deployment
echo "🔐 Security Pre-Flight Checklist"
echo ""

echo "1️⃣ Check for committed secrets:"
git log -p | grep -i "password\|secret" | wc -l
echo "   ✅ Should return: 0"
echo ""

echo "2️⃣ Check .env not in Git:"
git ls-files | grep ".env$" || echo "   ✅ .env not in Git"
echo ""

echo "3️⃣ Check SECRET_KEY length:"
python -c "import os; sk = os.getenv('SECRET_KEY', ''); print(f'   Length: {len(sk)} (min 32 required)')"
echo ""

echo "4️⃣ Check for weak passwords:"
grep -r "scanner:scanner" . --include="*.py" | wc -l || echo "   ✅ No weak passwords found"
echo ""

echo "5️⃣ Check CORS settings:"
grep "CORS_ORIGINS" backend/config.py
echo ""

echo "6️⃣ Backend health:"
timeout 5 python -m backend.app &
sleep 2
curl -s http://localhost:8000/health | grep -q "ok" && echo "   ✅ Backend responding" || echo "   ❌ Backend not responding"
pkill -f backend.app
echo ""

echo "✅ Pre-flight check complete!"
```

---

## 📋 BEFORE-AFTER CHECKLIST

### Before Production
- [ ] Generate new secrets (3 commands above)
- [ ] Remove `.env` from Git
- [ ] Verify no secrets in repo (command #7)
- [ ] Update `.env.example`
- [ ] Run health check (command #6)
- [ ] Create GitHub repository
- [ ] Push to GitHub safely

### After Production
- [ ] Configure monitoring (Sentry)
- [ ] Set up alerts (UptimeRobot)
- [ ] Enable automated backups
- [ ] Document runbooks
- [ ] Train team on incident response
- [ ] Schedule security reviews

---

## 🆘 TROUBLESHOOTING

### "ERROR: .env file still in Git"
```bash
# Check if actually removed
git ls-files | grep .env

# If still there, do full removal
git filter-branch --tree-filter 'rm -f .env' HEAD
git push origin --force
```

### "SECRET_KEY STILL DEFAULT"
```bash
# Check what's set
echo $SECRET_KEY
python -c "import os; print(os.getenv('SECRET_KEY'))"

# Update .env with new value
python -c "import secrets; print(secrets.token_hex(32))" > /tmp/new_key.txt
```

### "Backend won't start - JSON parsing error"
```bash
# Check .env format
cat .env | head -20

# Remove problematic lines
grep -i "CORS_ORIGINS" .env  # Remove if present

# Try simpler .env
rm .env
# Use the template from #3️⃣ above
```

### "Health endpoint returns error"
```bash
# Check all services
curl http://localhost:8000/health/full | python -m json.tool

# Check logs
python -m backend.app 2>&1 | grep -i "error\|warning"

# Check ports
netstat -ano | findstr ":8000"  # Windows
# or
lsof -i :8000  # Mac/Linux
```

---

## 📞 HELP REFERENCE

| Problem | Solution | Time |
|---------|----------|------|
| Secrets in Git | `git rm --cached .env` | 5 min |
| DEFAULT SECRET_KEY | Generate new via Python | 5 min |
| .env parse error | Remove CORS_ORIGINS line | 5 min |
| Backend won't start | Check DEBUG and SECRET_KEY | 10 min |
| Health check fails | Check ports and permissions | 10 min |
| Can't remove .env from history | Use `git filter-branch` | 30 min |

---

## 🎯 ESTIMATED TIME

| Phase | Task | Time |
|-------|------|------|
| **Day 1** | Generate secrets, remove .env, verify | 1 hour |
| **Day 2-3** | Code security fixes, testing | 4 hours |
| **Day 4** | GitHub setup and publication | 2 hours |
| **Day 5-7** | Infrastructure and deployment | 8-16 hours |
| **Day 8** | Monitoring and runbooks | 2 hours |
| **TOTAL** | **Full production readiness** | **17-25 hours** |

---

## ✅ SUCCESS INDICATORS

- ✅ No "SECURITY WARNING" messages on startup
- ✅ Health endpoints return 200 OK
- ✅ `git log --all --full-history -- .env` shows only removal
- ✅ All secrets generate and validate
- ✅ No secrets in `git diff` output
- ✅ Tests pass
- ✅ Documentation complete
- ✅ GitHub repository public and working
- ✅ Production deployment responding

---

**Last Updated:** 2026-05-24  
**Next Review:** Before each deployment  
**Questions?** See PRODUCTION_READINESS_SUMMARY.md or SECURITY_CHECKLIST.md
