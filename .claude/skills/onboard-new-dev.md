# /onboard-new-dev — Verify a new dev's environment is ready

Self-diagnostic for someone setting up the 24Defend repo for the first time
(or for an existing dev after a long break). Runs a checklist of expected
local state and prints `OK` or `FAIL` per item. No state changes — read-only.

## When to use

- Day 1, after cloning the repo and placing `aws.sh`
- After upgrading macOS / Xcode / Python (verify nothing rotted)
- Before reporting "the build is broken" — first rule out local environment

## Usage

```
/onboard-new-dev
```

No arguments. Run from anywhere.

## Commands

```bash
REPO="/Users/mgurmendez/git/24defend-mono"
PASS=0
FAIL=0

check() {
  local label="$1"
  local cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    echo "  OK    $label"
    PASS=$((PASS+1))
  else
    echo "  FAIL  $label"
    FAIL=$((FAIL+1))
  fi
}

echo "=== 24Defend onboarding check ==="
echo ""

echo "--- Repo layout ---"
check "Repo present at $REPO"            "test -d $REPO/.git"
check "backend/ exists"                  "test -d $REPO/backend/app"
check "ios/ exists"                      "test -d $REPO/ios/TwentyFourDefend"
check "ml/ exists"                       "test -d $REPO/ml"
check "infra/ exists"                    "test -d $REPO/infra"
check "www/ exists"                      "test -d $REPO/www"
check "research/ exists"                 "test -d $REPO/research"
check ".claude/skills/ exists"           "test -d $REPO/.claude/skills"
echo ""

echo "--- Required tooling ---"
check "git"                              "command -v git"
check "docker"                           "command -v docker"
check "docker daemon running"            "docker info"
check "docker-compose available"         "docker compose version || command -v docker-compose"
check "python3.12"                       "command -v python3.12"
check "aws cli v2"                       "aws --version 2>&1 | grep -q aws-cli/2"
check "xcodegen"                         "command -v xcodegen"
check "xcodebuild (Xcode installed)"     "command -v xcodebuild"
echo ""

echo "--- AWS credentials ---"
check "aws.sh.example template present"  "test -f $REPO/aws.sh.example"
check "aws.sh present at repo root"      "test -f $REPO/aws.sh"
if [ ! -f "$REPO/aws.sh" ] && [ -f "$REPO/aws.sh.example" ]; then
  echo "  HINT  Copy the template: cp $REPO/aws.sh.example $REPO/aws.sh"
  echo "        Then fill in dev IAM keys. See docs/aws-keys.md."
fi
check "aws.sh is gitignored"             "(cd $REPO && git check-ignore aws.sh)"
if [ -f "$REPO/aws.sh" ]; then
  source $REPO/aws.sh 2>/dev/null
fi
check "AWS_ACCESS_KEY_ID set"            'test -n "$AWS_ACCESS_KEY_ID"'
check "AWS_SECRET_ACCESS_KEY set"        'test -n "$AWS_SECRET_ACCESS_KEY"'
check "AWS_DEFAULT_REGION=us-east-1"     '[ "$AWS_DEFAULT_REGION" = "us-east-1" ]'
check "sts get-caller-identity works"    'aws sts get-caller-identity --output text'
ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ "$ACCOUNT" = "081856108753" ]; then
  echo "  OK    On dev account (081856108753)"
  PASS=$((PASS+1))
else
  echo "  FAIL  Account is '$ACCOUNT', expected 081856108753 — see docs/aws-keys.md"
  FAIL=$((FAIL+1))
fi
echo ""

echo "--- Backend Python venv ---"
check "backend/.venv exists"             "test -d $REPO/backend/.venv"
check "backend venv has fastapi"         "$REPO/backend/.venv/bin/python -c 'import fastapi'"
check "backend venv has pytest"          "$REPO/backend/.venv/bin/python -c 'import pytest'"
check "backend venv has aioboto3"        "$REPO/backend/.venv/bin/python -c 'import aioboto3'"
echo ""

echo "--- Backend tests pass ---"
if [ -d "$REPO/backend/.venv" ]; then
  if (cd $REPO/backend && .venv/bin/python -m pytest tests/ -q --tb=no 2>&1 | tail -5 | grep -q "passed"); then
    echo "  OK    pytest green"
    PASS=$((PASS+1))
  else
    echo "  FAIL  pytest failed — run 'cd backend && .venv/bin/python -m pytest tests/ -v' for detail"
    FAIL=$((FAIL+1))
  fi
else
  echo "  FAIL  backend/.venv missing — skipping pytest check"
  FAIL=$((FAIL+1))
fi
echo ""

echo "--- DynamoDB dev access ---"
check "Can describe 24defend-domains table" \
  "aws dynamodb describe-table --table-name 24defend-domains --region us-east-1 --output text"
echo ""

echo "--- CloudWatch logs access ---"
check "Can list defend-dev log groups" \
  "aws logs describe-log-groups --region us-east-1 --query 'logGroups[?contains(logGroupName, \`defend-dev\`)]' --output text | head -1"
echo ""

echo "--- iOS local check ---"
check "ios/project.yml present"          "test -f $REPO/ios/project.yml"
check "Xcode license accepted"           "xcodebuild -version"
check "iPhone simulator runtime"         "xcrun simctl list devicetypes 2>&1 | grep -q 'iPhone 15'"
echo ""

echo "--- Skills present ---"
for s in deploy deploy-backend-fast deploy-www status logs-backend check-domain clear-cached-verdict local-dev test-backend ios-build add-domain ingest-now; do
  check "/$s skill file"                 "test -f $REPO/.claude/skills/$s.md"
done
echo ""

echo "=== Summary ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "Fix the FAILs above, then re-run /onboard-new-dev. See ONBOARDING.md for setup help."
  exit 1
else
  echo "Environment looks good. Next: read ONBOARDING.md Day 2-3 reading list, then pick a task from research/improvements.md."
fi
```

## Interpreting common failures

| Failure | Fix |
|---------|-----|
| `docker daemon running` FAIL | Open Docker Desktop, wait for green status, retry |
| `python3.12` missing | `brew install python@3.12` (or use pyenv to install 3.12.x) |
| `xcodegen` missing | `brew install xcodegen` |
| `aws.sh present` FAIL | `cp aws.sh.example aws.sh` then paste dev IAM keys (request from tech lead via secure channel). Full guide: `docs/aws-keys.md`. Verify keys are for IAM user `bedrock24defend` on account 081856108753. |
| `aws.sh is gitignored` FAIL | Critical — your `aws.sh` is tracked by git. Stop, do NOT commit anything, remove from index (`git rm --cached aws.sh`), verify `.gitignore` contains `aws.sh`, and rotate the keys (see `docs/aws-keys.md` "Security guidelines"). |
| `sts get-caller-identity works` FAIL | Likely expired keys or wrong region. `source aws.sh` again, check `AWS_DEFAULT_REGION=us-east-1`. See `docs/aws-keys.md` "Common errors". |
| `On dev account (081856108753)` FAIL | Keys are valid but for the wrong account — replace `aws.sh`. See `docs/aws-keys.md`. |
| `backend/.venv exists` FAIL | `cd backend && python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-test.txt` |
| `pytest green` FAIL | Run with `-v` to see which test failed. If it's all of them, you probably have a Python or dependency mismatch — recreate the venv |
| `Can describe 24defend-domains table` FAIL | Either AWS creds are wrong or the user IAM policy doesn't grant DynamoDB read. Talk to Tech Lead — possibly a missing IAM grant |
| `iPhone 15 simulator runtime` FAIL | Open Xcode → Settings → Platforms → install iOS runtime |

## What this skill does NOT check

- Whether your `serper.conf` is valid (optional — Google search tool degrades
  gracefully without it)
- Whether you have signing certs for real-device iOS testing (separate setup;
  see `ios/DISTRIBUTION.md`)
- Bedrock model access (the IAM user has it by default; if you hit
  `AccessDenied` calling Bedrock, that's the account-level fix, not yours)
- Pre-commit hooks (none configured yet)

## Next step

When everything is OK, read `ONBOARDING.md` Day 2-3, then pick a task from
`research/improvements.md` and ship it.
