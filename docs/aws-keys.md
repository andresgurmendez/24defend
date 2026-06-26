# AWS keys — how 24Defend manages local credentials

This document covers how local AWS credentials work in this repo: why we use a
shell-sourced `aws.sh` file instead of `~/.aws/credentials`, how to obtain dev
keys for the first time, how to rotate them, and what to do when something
breaks.

> **TL;DR**: copy `aws.sh.example` to `aws.sh`, fill in the dev IAM keys
> (request from the founder / tech lead via a secure channel), `source aws.sh`
> before any AWS command. Never commit `aws.sh`.

---

## Why `aws.sh` and not `~/.aws/credentials`

The codebase's Claude Code skills (`/deploy`, `/deploy-backend-fast`,
`/logs-backend`, `/onboard-new-dev`, etc.) all `source aws.sh` before the AWS
calls they make. That is deliberate:

- **Explicit, opt-in scope.** Sourcing only affects the current shell. Other
  shells, other projects, and background processes do not inherit the dev
  account creds. There is zero risk of accidentally running an `aws` command
  against 24Defend resources while you were trying to do something for a
  different project.
- **One file, one account.** No profile gymnastics, no `AWS_PROFILE` mistakes,
  no "which profile is the default again?" The file at the repo root *is* the
  dev account.
- **Easy to detect.** If `aws sts get-caller-identity` fails or returns the
  wrong account, the cause is one of: forgot to `source`, file has stale keys,
  file is missing. There is no shared state with `~/.aws/credentials` to debug.
- **Auditable in one place.** Anyone reviewing the repo can find the only
  place credentials are loaded from. Skills always show `source aws.sh` as the
  first line.

`~/.aws/credentials` is fine if you're disciplined about profiles, but
the team agreed on `aws.sh` as the single source of truth for local dev. If
you prefer `~/.aws/credentials`, you must still set `AWS_PROFILE` explicitly
before every skill — the skills don't read profile config.

---

## Two-account model

| Environment | Account ID         | Auth method            | Used for                                |
|-------------|--------------------|------------------------|------------------------------------------|
| Dev         | `081856108753`     | Static IAM user keys   | All local development, dev ECS deploys   |
| Prod        | (separate, TBD)    | SSO (planned)          | Production deploys, prod log access      |

**Dev** uses a shared IAM user, `bedrock24defend`, with the policy set the
team needs for daily work: Bedrock invoke, DynamoDB read/write on
`24defend-*` tables, ECR push, ECS deploy, CloudWatch read, S3 read/write on
`24defend-*` buckets, Secrets Manager read.

**Prod** will use AWS SSO — temporary credentials issued via `aws sso login`,
no long-lived keys. The prod account ID and SSO portal URL will be filled in
once prod is provisioned; in the meantime, treat any "prod" task as needing
the tech lead's help.

There is no other account. If `aws sts get-caller-identity` shows anything
besides `081856108753`, your `aws.sh` is wrong.

---

## First-time setup

1. **Request dev keys from the founder / tech lead** via a secure channel.

   Acceptable: Signal, 1Password share, in-person on a USB drive.

   Not acceptable: Slack DM, email, GitHub, any SaaS support form, screenshot
   in a Notion doc. The keys grant full Bedrock + DynamoDB + ECS access on the
   dev account; treat them as production secrets even though the account is
   "dev".

2. **Copy the template** at the repo root:

   ```bash
   cd /Users/mgurmendez/git/24defend-mono
   cp aws.sh.example aws.sh
   chmod +x aws.sh
   ```

3. **Edit `aws.sh`** and paste the IAM key id and secret. Leave
   `AWS_SESSION_TOKEN` unset (the dev IAM user does not use STS). Leave
   `AWS_DEFAULT_REGION=us-east-1` — all resources are in `us-east-1`.

4. **Verify**:

   ```bash
   source aws.sh
   aws sts get-caller-identity
   ```

   Expected output:

   ```json
   {
     "UserId": "AIDA...",
     "Account": "081856108753",
     "Arn": "arn:aws:iam::081856108753:user/bedrock24defend"
   }
   ```

   If the account is anything other than `081856108753`, stop — the keys are
   for the wrong account.

5. **Run the onboarding check** to validate the rest of the toolchain:

   ```
   /onboard-new-dev
   ```

   It re-runs `aws sts get-caller-identity` plus DynamoDB and CloudWatch
   smoke tests.

---

## Daily use

Every shell that runs an AWS-related command starts with:

```bash
cd /Users/mgurmendez/git/24defend-mono
source aws.sh
```

The skills (`/deploy`, `/deploy-backend-fast`, `/logs-backend`, etc.) already
do this in their first step. If you're running raw `aws` CLI commands or
`cdk` from your own shell, you must `source aws.sh` yourself.

### Should I just put `source aws.sh` in my shell rc?

No. Don't. Reasons:

- It pollutes every shell, including ones where you're working on unrelated
  projects, with 24Defend dev credentials.
- It makes "did I source it?" invisible — when something breaks, you can't
  tell whether you have stale env vars from an old terminal.
- It defeats the explicit, opt-in design that motivated the `aws.sh` pattern
  in the first place.

If you want a shortcut, alias it:

```bash
alias defend='cd /Users/mgurmendez/git/24defend-mono && source aws.sh'
```

Then `defend` in any shell is the one-command "I want to work on 24Defend now".

---

## Rotation

### Static IAM user keys (current dev setup)

**Rotate every 90 days.** Process:

1. Ping the founder / tech lead and ask them to issue a new access key for
   the `bedrock24defend` IAM user.
2. Tech lead generates the new key in the IAM console, sends it via the same
   secure channel used for first-time setup.
3. Update `aws.sh` locally with the new id and secret.
4. Verify: `source aws.sh && aws sts get-caller-identity`.
5. Tech lead **deactivates and then deletes** the old key in IAM, after
   confirming everyone using the user has rotated. (AWS allows two active
   keys per user, which makes rotation zero-downtime.)

If you suspect a leak — committed by accident, pasted somewhere wrong, laptop
stolen — skip the schedule and rotate now. See
[Security guidelines](#security-guidelines) below.

### SSO temporary credentials (prod, planned)

When prod is wired up, the flow is:

```bash
aws sso login --profile defend-prod
# Then either:
#   export AWS_PROFILE=defend-prod
# or copy the resulting temporary creds into aws.sh (Option B in the template).
```

Tokens expire in ~12 hours; re-run `aws sso login` to refresh. There are no
long-lived prod keys to rotate.

---

## Common errors

| Error                                                                 | Cause                                  | Fix                                                                 |
|-----------------------------------------------------------------------|----------------------------------------|---------------------------------------------------------------------|
| `Unable to locate credentials. You can configure credentials by...`   | Did not source `aws.sh` in this shell  | `source /Users/mgurmendez/git/24defend-mono/aws.sh` and retry        |
| `ExpiredToken: The security token included in the request is expired` | SSO / STS session token expired        | Re-run `aws sso login`, or update `aws.sh` Option B with fresh creds |
| `InvalidClientTokenId: The security token included in the request is invalid` | Key id or secret is wrong (typo, stale, deleted)  | Verify against the secure-channel message; rotate if needed         |
| `AccessDenied` on a specific service                                  | IAM user policy doesn't grant it       | Talk to the tech lead; do not patch policies yourself                |
| `aws sts get-caller-identity` shows the wrong account                 | `aws.sh` has keys for a different account, or your shell has stale env vars from another project | Re-source `aws.sh`; if still wrong, replace the keys                  |
| Docker build fails: `no basic auth credentials` on ECR push            | ECR login expired (12h)                | Re-run `aws ecr get-login-password ... \| docker login ...` (in `/deploy-backend-fast`) |

For broader issues, see [troubleshooting.md](troubleshooting.md).

---

## Security guidelines

- **Never commit `aws.sh`.** It is in `.gitignore`. Run
  `git check-ignore aws.sh` to confirm before any commit. If you ever see
  `aws.sh` in `git status` as tracked, stop and investigate.
- **Never paste the keys** into Slack, email, GitHub issues, ChatGPT, Claude
  in a web browser, or any SaaS tool. The terminal you `source aws.sh` in is
  the only place they should appear.
- **Never reuse the dev keys for personal projects or other clients.** The
  IAM user is shared — your activity is attributable to the shared identity,
  not to you, which makes attribution and revocation hard.
- **If you suspect a leak**, do this in order:
  1. Tell the tech lead immediately (Signal / call, not Slack).
  2. The tech lead deactivates the key in the IAM console (one click).
  3. The tech lead issues a new key, distributes it.
  4. Everyone updates `aws.sh`.
  5. The compromised key is deleted from IAM.
- **If you find the keys in git history** — even on a feature branch, even on
  a fork — treat it as a leak. Rotate immediately. `git filter-repo` to scrub
  the history is helpful but not a substitute for rotation; assume the keys
  are public the moment they touch a `.git` object.
- **No secrets-in-comments.** Don't leave a "previous keys" block commented
  out in `aws.sh` for reference. Delete and rotate.

### What `aws.sh` should never contain

- Production credentials (prod uses SSO, not static keys; until prod exists,
  no prod creds should exist).
- Credentials for an account other than `081856108753`.
- Personal AWS keys (your own root account, etc.).
- Anything other than the four exports in `aws.sh.example`.
- Comments containing real key fragments, even old ones.

---

## AWS Console access

You may need console access for IAM management (rotation), CloudFormation
debugging, or one-off queries that are easier in the GUI than the CLI.

For the dev account, sign in as the `bedrock24defend` IAM user using the
account-level sign-in URL the tech lead provides. There is no dev SSO; do not
attempt to use the AWS SSO portal for the dev account.

For prod (once provisioned), use the SSO portal URL provided by the tech
lead. No IAM user sign-in on prod.

---

## See also

- `aws.sh.example` — the template you copy
- [ONBOARDING.md](../ONBOARDING.md) — full first-day setup
- [troubleshooting.md](troubleshooting.md) — broader debugging guide
- `.claude/skills/onboard-new-dev.md` — automated environment check
- `.claude/skills/deploy-backend-fast.md` — daily deploy command (uses `aws.sh`)
