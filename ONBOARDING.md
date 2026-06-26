# Onboarding — 24Defend

For someone joining the project. Plain checklist, no fluff. Should take ~1 day to get green, ~1 week to ship a first PR.

---

## Day 1 — Get the stack running locally

### Prerequisites (verify with `/onboard-new-dev` after setup)

- macOS (iOS work requires Xcode → Apple Silicon strongly preferred)
- Docker Desktop
- Python 3.12 (matches `backend/Dockerfile` and `backend/requirements.txt`)
- Xcode 15+ (for `ios/`) and `xcodegen` (`brew install xcodegen`)
- AWS CLI v2 (`brew install awscli`)
- `aws.sh` placed at the repo root with valid dev IAM keys — copy from `aws.sh.example`, request keys from the tech lead. Full setup, rotation, and security notes in [docs/aws-keys.md](docs/aws-keys.md).
- Access to GitHub repo via the `github-24defend` SSH host alias (separate key, do `ssh-add ~/.ssh/id_24defend`)

### Setup

1. **Clone the monorepo** and `cd` into it.
2. **Drop `aws.sh` at the root**. `cp aws.sh.example aws.sh`, fill in the dev IAM keys for account `081856108753` (IAM user `bedrock24defend`). The file is gitignored. Never commit it. Full setup, rotation, and security guidelines: [docs/aws-keys.md](docs/aws-keys.md).
3. **Bring up the backend** with the `/local-dev` skill or manually:
   ```bash
   source aws.sh
   cd backend && docker compose up --build
   ```
   API at http://localhost:9147, docs at http://localhost:9147/docs. Local DynamoDB runs in-memory in a sibling container — data resets on every restart.
4. **Run the backend tests**:
   ```bash
   cd backend && .venv/bin/python -m pytest tests/ -v
   ```
   Should print 160+ green. If the venv doesn't exist yet: `python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-test.txt`.
5. **Generate the iOS project and open it**:
   ```bash
   cd ios && xcodegen generate
   open TwentyFourDefend.xcodeproj
   ```
   Build the `TwentyFourDefend` scheme against the iPhone 15 simulator. NetworkExtension won't actually function in the simulator — only the UI runs there. Real device testing requires Apple Developer enrollment (see `ios/DISTRIBUTION.md`).

If any step fails, run `/onboard-new-dev` and read the output before pinging anyone.

---

## Day 2-3 — Read these in order

1. **[architecture.md](architecture.md)** — full system architecture. The longest doc but the most important. Skim sections you don't need yet; deep-read the iOS DNS interception flow and the backend `/check` decision path.
2. **[CLAUDE.md](CLAUDE.md)** — non-obvious patterns, footguns, and deployment notes. Short, dense, important.
3. **[research/improvements.md](research/improvements.md)** — backlog. Read this to understand what's missing and find a first task.
4. **[CHANGELOG.md](CHANGELOG.md)** — chronological history of what shipped and why. Helps you understand current decisions.
5. **[ios/DISTRIBUTION.md](ios/DISTRIBUTION.md)** — only if you're working on iOS / App Store / TestFlight.

---

## First task

Pick something small from `research/improvements.md` that's labeled as not-yet-implemented and doesn't require infra changes. Good starting candidates:
- Add a new brand/keyword to the rule engine (touches `ios/Shared/BrandRuleEngine.swift`, `ml/features.py`, and the heuristics tool in the backend — all three lists must agree)
- Add a domain to the infrastructure allowlist (`ios/Shared/DomainChecker.swift`)
- Add a new feed source in `backend/app/ingestion/sources.py`
- Improve a backend test, or add one for an uncovered branch

Avoid for week 1: anything touching `infra/` (CDK), `backend/app/scheduler.py`, the LangGraph agent prompt, or iOS NetworkExtension internals. Those have sharp edges — pair with someone first.

---

## Conventions you need to know on Day 1

### Legal entity — TONLER S.A.S.

The project is **operated by TONLER S.A.S.** (Uruguay), not an individual. All public-facing materials — App Store metadata, privacy policies, contracts, support replies — must use this name. Public contact is `dev@24defend.com`. Detailed registry data lives in `CLAUDE.md` and `CHANGELOG.md`; don't copy it into new docs unless required by a regulator.

### Roles (no names — ask in onboarding)

- **Founder / Tech Lead** — owns architecture, agent prompt, infra, App Store account
- **CEO (in process)** — business, legal, commercial relationships
- Until the team grows, expect to wear multiple hats. Default to talking to the Tech Lead first for technical questions.

### Communication

- Public email: `dev@24defend.com` (use this for anything that touches users, partners, or external systems)
- Internal Slack / on-call channels: ask the Tech Lead

---

## Footguns — know these before you change code

These are the ones that bite hardest. Most are documented inline in `CLAUDE.md`; flagged here so you see them on Day 1.

### `xcodegen generate` overwrites Info.plist

After `cd ios && xcodegen generate`, restore `CFBundleDisplayName` in the app's `Info.plist` and the `NSExtension` dict in the tunnel's `Info.plist`. xcodegen blows these away every time. The `/ios-build` skill encodes this.

### ARM vs AMD64 Docker

Macs are ARM, Fargate is AMD64. The Dockerfile pins `FROM --platform=linux/amd64`. If you remove that or build with a different flag, the image runs locally but crashes on Fargate with `exec format error`. Always `docker build --platform linux/amd64` when pushing to ECR.

### AWS creds in `aws.sh`

Dev AWS creds live in `aws.sh` at the repo root (gitignored). `source aws.sh` before any AWS CLI command. CI is broken (missing `AWS_DEPLOY_ROLE_ARN`), so deploys go through `/deploy-backend-fast` from your laptop. **Never commit `aws.sh`.** See [docs/aws-keys.md](docs/aws-keys.md) for setup, rotation, leak response, and the dev/prod account model.

### Bloom filter is signed-mod, not unsigned

The Swift bloom filter uses Python-style signed int32 modulo (`pythonMod` in `ios/Shared/`). Use unsigned modulo and lookups will silently miss. If you ever touch the bloom filter, run the cross-validation tests in `backend/tests/test_cross_validation.py` against `mmh3_ground_truth.json` and `python_feature_ground_truth.json`.

### ML classifier is silent

The ML model never produces a user-facing warning — it only submits suspicious domains to the backend in the background. Brand rule engine warnings are the only user-facing ones. Don't add UI surfaces for ML output without product approval.

### CI is broken

GitHub Actions can't deploy (missing `AWS_DEPLOY_ROLE_ARN` secret). Use `/deploy-backend-fast` or `/deploy` from your laptop. Don't trust a green "pushed to main" as "deployed."

### Secrets / API keys

Never commit `aws.sh`, `serper.conf`, App Store API keys, or anything resembling a credential. Use Secrets Manager for runtime values (`/deploy` documents how). Pre-commit hooks are not yet wired up; review your diff before pushing.

---

## When you're stuck

1. Search `CLAUDE.md` and `architecture.md` first — most "how does this work" answers are there. For a quick visual, [docs/architecture-diagram.md](docs/architecture-diagram.md).
2. Search `CHANGELOG.md` — most "why is this like this" answers are there.
3. Search [docs/troubleshooting.md](docs/troubleshooting.md) for common errors and fixes by area.
4. Run the relevant skill (`/status`, `/logs-backend errors`, `/check-domain <d>`) before assuming the system is broken.
5. If you're still stuck, post in the team channel with what you tried.

---

## What "done" looks like for onboarding

- [ ] `/onboard-new-dev` outputs all green
- [ ] Backend tests pass locally
- [ ] iOS app builds and runs in the simulator
- [ ] You've read `architecture.md` and `CLAUDE.md`
- [ ] You opened your first PR (see [CONTRIBUTING.md](CONTRIBUTING.md))

Next: pick a task from `research/improvements.md` and start.
