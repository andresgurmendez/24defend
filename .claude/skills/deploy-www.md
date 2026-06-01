# /deploy-www — Deploy the website to S3 + CloudFront

Syncs `www/` to S3 and creates a CloudFront invalidation. Used for
content/copy/legal updates (privacy policy, footer, landing page text)
and the only fast way to push web changes — no CDK needed.

## When to use

- You edited any file in `www/` (index.html, privacy-*.html, icon.png)
- You need the change visible on www.24defend.com immediately
- You don't need infrastructure changes (cert, CloudFront behavior, etc.)

## Prerequisites

- AWS creds active: `source /Users/mgurmendez/git/24defend-mono/aws.sh`
- Account 081856108753 (dev), region us-east-1

## Resources

- **S3 bucket**: `s3://24defend-www-dev/`
- **CloudFront distribution ID**: `E2NV1T0DZ96AY`
- **Aliases**: www.24defend.com, 24defend.com

## Usage

```
/deploy-www
```

## Commands

```bash
cd /Users/mgurmendez/git/24defend-mono
source aws.sh

# 1. Sync www/ to S3
aws s3 sync www/ s3://24defend-www-dev/ \
  --exclude ".DS_Store" \
  --cache-control "max-age=300" \
  --delete

# 2. Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id E2NV1T0DZ96AY \
  --paths "/*" \
  --query 'Invalidation.{Id:Id, Status:Status}' \
  --output json

# 3. (Optional) Wait for invalidation to complete and verify
INVALIDATION_ID="<paste from step 2>"
aws cloudfront get-invalidation \
  --distribution-id E2NV1T0DZ96AY \
  --id $INVALIDATION_ID \
  --query 'Invalidation.Status' --output text

# 4. Verify the live site shows the change
curl -s https://www.24defend.com | grep -oE "(<your search term>)"
```

## Gotchas

### Invalidation takes 1-3 min to propagate
The S3 sync is instant but CloudFront takes a bit. If you check immediately
after, you may still see cached content. To bypass cache while testing, hit
S3 directly:
```bash
curl -s https://24defend-www-dev.s3-website-us-east-1.amazonaws.com/
```

### --delete removes files not in www/
The `--delete` flag deletes anything in the bucket that's not in the local
folder. This is what we want (keeps S3 in sync), but be careful if you added
files directly to S3 outside the repo — they will be deleted.

### Cache-control 5 min
We set `max-age=300` so that even without explicit invalidation, content
refreshes every 5 minutes. The explicit invalidation in step 2 forces it
faster.

### CloudFront cost
Each invalidation path counts. `/*` is one path (free up to 1000/month per
distribution). Don't list 50 paths individually; use `/*`.

## What lives in www/

```
index.html           landing page (Spanish, with TONLER S.A.S. in footer)
privacy.html         meta-refresh redirect to privacy-es.html
privacy-es.html      Spanish privacy policy
privacy-en.html      English privacy policy
icon.png             24Defend logo
```

The footer of `index.html` and the Contact section of both privacy policies
identify TONLER S.A.S. as the operator (RUT 220621480018, Miguel Barreiro
3236 Apto 602, Montevideo). This is required for Apple Developer
organization enrollment verification.

Public contact email on the site is `dev@24defend.com` (filterable alias).
Personal/corporate email `maximo@24defend.com` is NOT shown publicly to
avoid scraping.
