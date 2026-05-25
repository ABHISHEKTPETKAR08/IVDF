# GitHub Publication & CI/CD Setup Guide

> **IMPORTANT: Complete SECURITY_CHECKLIST.md BEFORE proceeding**

---

## Phase 1: Local Git Preparation

### 1.1 Verify Repository Status

```powershell
cd "C:\ABHISHEK DOC\Cyber-mini\vulnerability-scanner"

# Check current Git status
git status

# Show all files (including gitignored)
git ls-files --others --exclude-standard

# List all tracked files that shouldn't be tracked
git ls-files | grep -E "\.env|\.pem|\.key|secrets"
```

**Expected Output:**
- `.env` should NOT appear in `git ls-files`
- Only `.env.example` should be tracked

### 1.2 Remove `.env` from Git History (if accidentally committed)

```powershell
# Check if .env was ever committed
git log --all --full-history -- .env

# If output shows commits, remove from history
git rm --cached .env
git commit -m "Remove .env with secrets from repository"

# Force push if needed (only if repo hasn't been cloned by others)
git push --force origin main
```

### 1.3 Verify .gitignore

```powershell
# Check .gitignore content
cat .gitignore

# Test gitignore rules
git check-ignore -v .env
git check-ignore -v "*.pyc"
git check-ignore -v "venv/"

# Should output: .env:.gitignore:15    .env
# Format: path:.gitignore:linenum path
```

### 1.4 Create Local Production Secrets

```powershell
# Create .env.local for local production testing (NEVER commit this)
cp .env.example .env.local

# Edit with actual values
notepad .env.local

# Verify it's gitignored
echo ".env.local" >> .gitignore
git check-ignore -v .env.local
```

---

## Phase 2: Remote Repository Setup

### 2.1 Create GitHub Repository

1. Go to https://github.com/new
2. **Repository Name:** `vulnerability-scanner` (or your preference)
3. **Description:** "Intelligent Vulnerability Detection and Analysis Framework"
4. **Visibility:** `Public` (for open-source) or `Private` (for internal use)
5. **Initialize:** ❌ DO NOT initialize with README (we have our own)
6. **Click:** Create Repository

### 2.2 Add GitHub Remote

```powershell
# Option 1: HTTPS (easier for first-time, password-protected)
git remote add origin https://github.com/YOUR-USERNAME/vulnerability-scanner.git

# Option 2: SSH (recommended if you have SSH keys configured)
git remote add origin git@github.com:YOUR-USERNAME/vulnerability-scanner.git

# Verify remote
git remote -v
# Output should show:
# origin  https://github.com/YOUR-USERNAME/vulnerability-scanner.git (fetch)
# origin  https://github.com/YOUR-USERNAME/vulnerability-scanner.git (push)
```

### 2.3 Configure Git User (if not already done)

```powershell
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Verify
git config --global --list | grep user
```

---

## Phase 3: First Push to GitHub

### 3.1 Create Main Branch and Push

```powershell
# Rename default branch to 'main' (if using older Git)
git branch -M main

# Push all commits to GitHub
git push -u origin main

# Verify
git branch -v
# Output: * main 1234567 Your latest commit message
```

### 3.2 Verify Push Success

```powershell
# Check remote status
git status
# Output: Your branch is up to date with 'origin/main'.

# View remote branches
git branch -r
# Output: origin/main

# Verify remote has all commits
git log --oneline origin/main | head -5
```

---

## Phase 4: GitHub Configuration

### 4.1 Add Repository Metadata

1. **Go to:** Repository Settings → Details
2. **Add Description:** "Production-grade Python cybersecurity assessment framework"
3. **Add Topics:**
   - `cybersecurity`
   - `vulnerability-scanning`
   - `penetration-testing`
   - `nmap`
   - `fastapi`
   - `python`
4. **Click:** Save

### 4.2 Create Security Files

#### SECURITY.md (Vulnerability Reporting)

```powershell
# File is already created in root. Verify it contains:
cat SECURITY.md
```

If not exist, create:

```markdown
# Security Policy

## Reporting a Vulnerability

⚠️ **PLEASE DO NOT report security vulnerabilities publicly via GitHub Issues**

Instead, follow the responsible disclosure process:

1. **Email:** security@your-domain.com
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)

3. **Expected Response:** Within 48 hours

## Supported Versions

Currently supported for security updates:
- Version 1.0.0 and later

## Security Practices

- All dependencies are regularly scanned for CVEs
- Code is reviewed before release
- Security updates are applied immediately
- Users are notified of critical issues

## 12Factor Compliance

This project follows 12Factor app principles for security:
- Configuration via environment variables
- No secrets in source code
- Credentials never logged
- Secure defaults

## Thank You

We appreciate security researchers who responsibly disclose vulnerabilities.
```

#### LICENSE

```powershell
# Check if LICENSE exists
cat LICENSE

# If not, create MIT license (recommended for open-source):
# Go to: https://github.com/YOUR-USERNAME/vulnerability-scanner/community/license
# Select "MIT License" and commit
```

#### CONTRIBUTING.md

```markdown
# Contributing to IVDAF

Contributions are welcome! Please follow these guidelines:

## Development Setup

```bash
git clone https://github.com/YOUR-USERNAME/vulnerability-scanner.git
cd vulnerability-scanner
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r backend/requirements.txt
```

## Security

- Never commit secrets or credentials
- Use environment variables for configuration
- Run security checklist before submitting PR

## Code Standards

- Format with `black`
- Lint with `pylint`
- Test with `pytest`
- Type hints required

## Submit Pull Request

1. Fork repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to fork: `git push origin feature/your-feature`
5. Submit Pull Request on GitHub
```

### 4.3 Protect Main Branch

1. **Go to:** Settings → Branches
2. **Branch Protection Rules:** Click "Add rule"
3. **Branch Name Pattern:** `main`
4. **Enable:**
   - ✅ Require pull request reviews before merging (1 review)
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - ✅ Include administrators in restrictions (optional)
5. **Click:** Create

### 4.4 Set Up GitHub Actions (Optional CI/CD)

Create `.github/workflows/security.yml`:

```yaml
name: Security Checks

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install bandit safety pip-audit
      
      - name: Check for secrets
        run: pip install detect-secrets && detect-secrets scan --baseline .secrets.baseline
      
      - name: Run Bandit (security linter)
        run: bandit -r backend/ -ll
      
      - name: Check for vulnerabilities
        run: pip-audit
```

---

## Phase 5: Documentation Finalization

### 5.1 Update README.md

Add security notice:

```markdown
## ⚠️ Security Notice

This tool is designed for **educational purposes and authorized security testing only**.

**NEVER** use this tool against systems you do not own or have explicit written permission to test.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

## Prerequisites

- Python 3.11+
- **Optional:** nmap (install via `winget install Insecure.Nmap` or https://nmap.org/download)

## Quick Start

1. Clone repository
2. Copy `.env.example` to `.env` and configure
3. Run backend: `python -m backend.app`
4. Run frontend: `streamlit run frontend/dashboard.py`

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for production deployment.
```

### 5.2 Create README for Docs

```powershell
# Ensure all documentation files exist
ls -Name | grep -E "README|DEPLOYMENT|GITHUB|SECURITY"

# Should output:
# README.md
# DEPLOYMENT_GUIDE.md
# GITHUB_SETUP.md (this file)
# SECURITY_CHECKLIST.md
```

---

## Phase 6: Pre-Push Verification

### 6.1 Final Security Scan

```powershell
# Scan for any remaining secrets
$secretPatterns = @("password", "secret", "key", "token", "api_key", "CHANGE-ME")
foreach ($pattern in $secretPatterns) {
    Write-Host "Searching for: $pattern" -ForegroundColor Yellow
    git grep -i "$pattern" | grep -v "\.example\|SECURITY_CHECKLIST\|README"
}

# Should return NOTHING (or only matches in example/doc files)
```

### 6.2 Check for Large Files

```powershell
# Find files > 10MB
git ls-files -s | awk '{print $4}' | xargs ls -lh | awk '$5 ~ /[0-9]+M|[0-9]+G/'

# Should be empty
```

### 6.3 Verify Git Log

```powershell
# Show recent commits (should not contain secrets)
git log --oneline -10

# Full commits with changes
git log -p origin/main...HEAD | head -100
```

---

## Phase 7: Push to GitHub

### 7.1 Push All Changes

```powershell
# Final status check
git status
# Should show: On branch main, Your branch is ahead of 'origin/main' by X commits

# Push to GitHub
git push origin main

# Verify
git log --oneline -5
git log --oneline -5 origin/main
# Both should show same recent commits
```

### 7.2 GitHub Verification

1. Go to: https://github.com/YOUR-USERNAME/vulnerability-scanner
2. Verify:
   - ✅ All files present
   - ✅ `.env` NOT visible in repository
   - ✅ `.env.example` IS visible
   - ✅ README.md displays correctly
   - ✅ SECURITY.md visible
   - ✅ DEPLOYMENT_GUIDE.md visible
   - ✅ Commit history looks clean (no secrets)

---

## Phase 8: Post-Publication

### 8.1 Enable GitHub Features

1. **Settings → General:**
   - ✅ Discussions (for community Q&A)
   - ✅ Sponsorships (if desired)

2. **Settings → Features:**
   - ✅ Issues (for bug reports)
   - ✅ Wikis (for documentation)

3. **Settings → Pages (if creating project site):**
   - Source: `Deploy from a branch`
   - Branch: `main` / `docs` folder

### 8.2 Announce Publication

```markdown
# Share on:
- HackerNews (https://news.ycombinator.com/submit)
- Reddit (r/cybersecurity, r/Python, r/InfoSec)
- Twitter/LinkedIn (with link)
- Product Hunt (https://www.producthunt.com)
- Dev.to (https://dev.to)
```

### 8.3 Monitor for Issues

```powershell
# Set up GitHub notifications
# GitHub Settings → Notifications → Email frequency
# Select: Participating and @mentions

# Watch your repository for issues/PRs
```

---

## Troubleshooting

### Problem: "fatal: remote origin already exists"

```powershell
# Solution: Remove and re-add
git remote remove origin
git remote add origin https://github.com/YOUR-USERNAME/vulnerability-scanner.git
```

### Problem: "Permission denied (publickey)" with SSH

```powershell
# Solution: Use HTTPS instead
git remote set-url origin https://github.com/YOUR-USERNAME/vulnerability-scanner.git
```

### Problem: ".env accidentally committed"

```powershell
# Solution: Remove from history
git rm --cached .env
git commit -m "Remove .env"
git push --force origin main

# WARNING: Force push can cause issues if others have cloned
# Better: Rotate all secrets immediately
```

### Problem: "Large files detected"

```powershell
# Solution: Remove from Git
git rm --cached large_file.db
echo "large_file.db" >> .gitignore
git commit -m "Remove large file"

# Add to .gitignore and store on cloud storage
```

---

## Completed Checklist

- [ ] `.env` removed from Git
- [ ] `.gitignore` properly configured
- [ ] SECURITY_CHECKLIST.md completed
- [ ] SECURITY.md created
- [ ] LICENSE added
- [ ] CONTRIBUTING.md added
- [ ] GitHub repository created
- [ ] Remote added locally
- [ ] All commits pushed
- [ ] Branch protection enabled
- [ ] Security files visible on GitHub
- [ ] README updated with security notice
- [ ] Team notified of publication

---

**Next Steps:**
1. Set up continuous deployment (see DEPLOYMENT_GUIDE.md)
2. Configure monitoring and alerts
3. Set up automated dependency scanning
4. Plan release schedule

---

**Last Updated:** 2026-05-24
