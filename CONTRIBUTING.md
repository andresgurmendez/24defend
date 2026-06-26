# Contributing

How we work on 24Defend. Read once; come back when in doubt.

---

## Branching

- `main` is protected. Do not push directly.
- Feature branches off `main`. Prefix with intent:
  - `feat/` — new functionality (e.g., `feat/safe-browsing-v5`)
  - `fix/` — bug fix (e.g., `fix/bloom-signed-mod`)
  - `chore/` — tooling / deps / refactor with no user-facing change
  - `docs/` — docs-only
- Rebase onto `main` before opening / updating a PR. Avoid merge commits in feature branches.

---

## Commit messages

Imperative mood, short, scoped.

```
<scope>: <what changed, in present tense>

[optional body — explain why, link to issue, paste relevant logs]
```

Examples:
```
backend: clear stale verdicts when prompt changes
ios: restore CFBundleDisplayName after xcodegen
ml: include puntos/premio in PHISHING_WORDS
docs: document ARM vs AMD64 Docker footgun
```

Scopes we use: `backend`, `ios`, `ml`, `infra`, `www`, `docs`, `ci`, `skills`. Mix is fine for a single logical change touching two areas — pick the dominant one.

If the commit fixes a tracked issue, reference it: `fix: handle empty bloom file (closes #42)`.

Avoid `wip`, `update`, `stuff`, `fix bug`, or anything that doesn't say what changed.

---

## Pull Request flow

1. Open the PR against `main` from your feature branch.
2. Title follows the same format as commits.
3. Body should include:
   - **What** changed
   - **Why** (link to the backlog item in `research/improvements.md` or the bug report)
   - **How to verify** (commands, manual steps, screenshots if iOS UI)
   - **Risk** (what could break? any infra changes?)
4. At least **1 review** required before merge.
5. CI must pass — except CI is broken right now (missing `AWS_DEPLOY_ROLE_ARN`). Until it's fixed, reviewers verify locally and we rely on `/deploy-backend-fast` to catch problems before they ship.
6. Squash-merge by default. Multi-commit merges are fine if each commit is meaningful and stands on its own.

### Code review checklist (reviewer perspective)

- [ ] Tests pass locally (`cd backend && .venv/bin/python -m pytest tests/ -v`)
- [ ] New behavior has at least one test
- [ ] No secrets, API keys, personal emails, customer data, or PII in the diff
- [ ] No `aws.sh`, `serper.conf`, `*.env` accidentally staged
- [ ] iOS changes: did the PR run `xcodegen generate` and restore `Info.plist`? (Diff should not include the regenerated `.xcodeproj` mess if it was clean before — check.)
- [ ] Docs updated if behavior is non-obvious (CLAUDE.md, architecture.md, the skill that depends on it)
- [ ] Conventions preserved: brand lists in `BrandRuleEngine.swift`, `ml/features.py`, and the backend heuristics tool stay in sync

---

## Testing

### Backend

160+ tests. Always run:

```bash
cd backend
.venv/bin/python -m pytest tests/ -v
```

Run a single test:

```bash
.venv/bin/python -m pytest tests/test_check.py::test_known_blacklist_blocks -v
```

DynamoDB is mocked in-process (`tests/conftest.py` — dict-backed `FakeTable`). No moto, no localstack. Bedrock is mocked too. Tests should be fast (< 30s total). If you write a test that requires real AWS, mark it `@pytest.mark.skip` by default with a comment explaining how to enable.

See `/test-backend` for more detail.

### iOS

Optional but encouraged. Tests live in `ios/Tests/`. Run from CLI:

```bash
cd ios
xcodebuild test -scheme TwentyFourDefend -destination 'platform=iOS Simulator,name=iPhone 15'
```

There are ground-truth fixtures (`mmh3_ground_truth.json`, `python_feature_ground_truth.json`) used to assert Swift and Python implementations agree. Don't break these without intent.

### ML

```bash
cd ml
.venv/bin/python train.py
```

Prints classification metrics. If accuracy drops noticeably, investigate before merging.

---

## Code style

### Python (backend, ml)

- Format with `black` (line length: default 88)
- Lint with `ruff` (rules: `E`, `F`, `I`, `B`)
- Type hints encouraged but not enforced — add them for public functions
- Don't over-engineer. We optimize for readability; abstraction comes only when there's a second concrete case

```bash
cd backend && .venv/bin/python -m black app/ tests/ && .venv/bin/python -m ruff check app/ tests/
```

### Swift (iOS)

- Default Xcode formatting
- SwiftUI over UIKit unless there's a reason
- The packet tunnel and the app share `ios/Shared/` — keep it pure (no UIKit imports, no UI types)

### Markdown (docs)

- Sentence-case headings
- Tables where they help; prose otherwise
- No emojis in committed code or docs unless explicitly requested

---

## Secrets

- **Never commit credentials.** This includes `aws.sh`, `serper.conf`, App Store API keys, Apple Push certs, anything in `~/.aws/credentials`.
- `aws.sh` and `serper.conf` are gitignored. Verify with `git status` before pushing.
- Runtime secrets live in AWS Secrets Manager (see `/deploy` skill). The Fargate task reads them on container start.
- If you accidentally commit a credential, rotate it immediately and then squash/rewrite history. Don't just delete the line.

---

## What to ask before opening a PR

- Does this need an `architecture.md` update? (anything changing the request flow, persistence model, or external dependency: yes)
- Does this need a `CHANGELOG.md` entry? (anything user-visible, anything affecting deploys: yes)
- Does this need a new skill? (any new repeated ops command: probably yes)
- Did I run `/status` after deploying to verify the change? (if you deployed: yes)

---

## Common rejection reasons (review feedback you can avoid)

- Modifying bloom filter logic without running `test_cross_validation.py`
- Adding to one brand list (Swift / Python / backend) without updating the other two
- Touching `xcodegen` output without restoring `Info.plist`
- Hardcoding a domain to fix one false positive — usually the fix belongs in the infrastructure allowlist or the agent prompt, not in the diff path you chose
- Pulling in a new pip dependency without thinking about Fargate cold-start size

---

When in doubt, lean toward small PRs that are easy to revert.
