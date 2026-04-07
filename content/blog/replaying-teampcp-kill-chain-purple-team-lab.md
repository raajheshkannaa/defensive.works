# Replaying the TeamPCP Kill Chain: A Purple Team Lab Walkthrough

*April 2026*

In late February 2026, the TeamPCP threat actor compromised a privileged token from Aqua Security's CI environment. On March 1, Aqua disclosed and rotated credentials, but the rotation was not atomic. By March 19, the attacker force-pushed malicious code to 76 of 77 tags on the `trivy-action` GitHub Action (CVE-2026-33634, CVSS 9.4). Every downstream pipeline that referenced `@v1` silently ran attacker code the next time it triggered.

The result: 66+ npm packages infected, the EU Commission breached (92GB exfiltrated per CERT-EU), and hundreds of thousands of credentials potentially exposed across five ecosystems.

Wiz CIRT documented the AWS post-compromise activity starting March 19: systematic enumeration of IAM, ECS, S3, and Secrets Manager, followed by ECS Exec pivots into running containers to exfiltrate data.

I built [TeamPCP Goat](https://github.com/raajheshkannaa/teampcp-goat) to replay the two most critical phases of this campaign in a controlled environment. The lab models the likely PwnRequest entry pattern and replicates the documented AWS post-exploitation tradecraft. Not the full cascade, but the entry point and the pivot: CI/CD credential theft feeding into AWS post-exploitation.

Every exploit step ships with the detection query that catches it. GitHub audit log queries for the CI/CD side, CloudTrail Athena queries for the AWS side.

## What the Lab Covers

Two modules. Six flags. The output of Module 1 is the input to Module 2.

**Module 1** replicates the CI/CD exploitation: the `pull_request_target` PwnRequest and the mutable tag poisoning. You run it locally with `act` (a local GitHub Actions runner). No real GitHub repo needed. You capture two flags by demonstrating that your modified entrypoint runs with full access to CI secrets.

**Module 2** replicates the AWS post-exploitation. You start with stolen CI/CD credentials that can list every service in the account but cannot read any data. You enumerate IAM, ECS, S3, Secrets Manager, EC2, and Lambda. You discover an ECS cluster with `enableExecuteCommand: true` on a running task. You pivot into the container, extract the task role's temporary credentials from the metadata endpoint, and use those to download customer data from S3 and production API keys from Secrets Manager.

The CI/CD credentials give you reconnaissance but not access. You need to find the pivot path to get to actual data.

## Module 1: CI/CD Exploitation

### The PwnRequest

The vulnerable workflow uses `pull_request_target` as its trigger. This event runs in the context of the base repository, which means it has access to repository secrets. The problem is what happens next.

```yaml
# Step 1: checks out base branch (safe)
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.base.sha }}

# Step 2: checks out the PR head (attacker-controlled)
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}
    clean: false
```

After Step 2, the working directory contains the attacker's code. Step 3 runs `entrypoint.sh` from that directory. The attacker's version of `entrypoint.sh` runs with the base repository's secrets loaded as environment variables.

In the lab, you replace the legitimate entrypoint with a version that detects credential environment variables:

```bash
for VAR in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY GITHUB_TOKEN DEPLOY_PAT; do
  VAR_VALUE="${!VAR:-}"
  if [ -n "${VAR_VALUE}" ]; then
    echo "[+] FOUND: ${VAR} (length: ${#VAR_VALUE})"
  fi
done
```

You run this with `act`, passing fake secrets on the command line. The output shows all four credential types detected. First flag captured.

### Defender's Side: Audit Log Detection

After capturing the flag, flip to defense. Two separate data sources matter here.

**Tag force-push detection (audit log):**

```bash
gh api "orgs/{org}/audit-log?phrase=action:git.push&include=git" --paginate | \
  jq '.[] | select(.data.forced == true and (.data.ref | startswith("refs/tags/")))'
```

**Workflow run detection (Actions API):**

```bash
gh api "repos/{owner}/{repo}/actions/runs" --paginate | \
  jq '.workflow_runs[] | select(.event == "pull_request_target") |
      {id: .id, actor: .actor.login, head_sha: .head_sha, conclusion: .conclusion}'
```

Three signals, across two telemetry sources:

1. Force-pushes to `refs/tags/` on any action repository (audit log)
2. `pull_request_target` workflow runs triggered by accounts outside the org (Actions API)
3. Workflow runs where the head SHA does not match any commit in the base repository (Actions API)

The fix: pin every GitHub Action to a full commit SHA.

```yaml
# Before (vulnerable to tag poisoning)
- uses: actions/checkout@v4

# After (immutable reference)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

### Tag Poisoning

The second exercise demonstrates why mutable tags are dangerous. The consumer pipeline references a third-party action at `@v1`. The tag-poison script simulates what a poisoned action would detect about the CI environment: which credential types exist, which credential files are present, and the runner's fingerprint.

```bash
bash modules/01-cicd-exploitation/exploit/tag-poison.sh
```

The script writes the second flag and produces a bridge file (`harvested_creds.json`) that Module 2 consumes. If Terraform infrastructure is deployed, the bridge file auto-populates with the real stolen credentials. No manual credential copying needed.

## Module 2: AWS Post-Exploitation

### Credential Validation

Every post-exploitation engagement starts the same way. Confirm what you have.

```bash
aws sts get-caller-identity
```

```json
{
  "UserId": "AIDA5MNNXDNLPVGTT3MH5",
  "Account": "920024193878",
  "Arn": "arn:aws:iam::920024193878:user/teampcp-goat-cicd-svc"
}
```

You are the CI/CD service account. `GetCallerIdentity` was also the first call in the Wiz CIRT post-compromise timeline. It is always logged by CloudTrail. Attackers call it anyway because they need to confirm what they have before spending time on enumeration.

### Enumeration

The enumeration script replicates the API call pattern documented by Wiz CIRT from the March 20 post-compromise activity:

```
Phase 1: IAM (ListUsers, ListRoles, ListAttachedUserPolicies)
Phase 2: S3 (ListBuckets, GetBucketPublicAccessBlock)
Phase 3: ECS (ListClusters, ListTaskDefinitions, DescribeTasks)
Phase 4: Secrets (ListSecrets)
Phase 5: EC2/Lambda (DescribeInstances, ListFunctions)
```

The output shows every resource in the account. The ECS section reveals a running task with `enableExecuteCommand: true`. That is the pivot point.

The enumeration report saves to `.teampcp/aws-enumeration-report.json`. Third flag captured.

### Defender's Side: CloudTrail Query 1

The enumeration burst is detectable. This query covers the IAM and STS portion of the pattern. A CI/CD role that calls `ListUsers` and `ListRoles` alongside `GetCallerIdentity` is not behaving like a deployment pipeline.

```sql
SELECT
    useridentity.arn AS actor_arn,
    eventtime,
    eventsource,
    eventname,
    sourceipaddress AS source_ip
FROM cloudtrail_logs
WHERE
    (eventsource = 'iam.amazonaws.com' OR eventsource = 'sts.amazonaws.com')
    AND eventname IN ('GetCallerIdentity', 'ListUsers', 'ListRoles',
                      'ListPolicies', 'ListAttachedRolePolicies')
    AND errorcode IS NULL
ORDER BY useridentity.arn, eventtime;
```

Detection rule: flag any identity that calls 4+ distinct IAM read APIs within a 5-minute window. The lab's Query 5 (full chain correlation) covers the broader pattern across IAM, ECS, S3, and Secrets Manager in a single query.

The remediation: CI/CD roles should only have the permissions the pipeline needs. Typically that is `ecr:GetAuthorizationToken`, `ecs:UpdateService`, and `s3:PutObject` to one deployment bucket. Use IAM Access Analyzer to generate least-privilege policies from actual usage logs.

### The ECS Exec Pivot

This is the critical phase. The CI/CD credentials can list every resource in the account but cannot call `s3:GetObject` or `secretsmanager:GetSecretValue`. The attackers needed a different identity with broader permissions. They found it inside the running container.

```bash
aws ecs execute-command \
  --cluster teampcp-goat-cluster \
  --task <task-arn> \
  --container app \
  --interactive \
  --command "printenv FLAG_ECS_EXEC"
```

Note: ECS Exec requires the [AWS Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) installed locally. The lab's `make preflight` checks for this and prints install instructions for your platform.

Once inside the container, the attacker extracts the ECS task role's temporary credentials from the container metadata endpoint:

```python
import urllib.request, os
url = "http://169.254.170.2" + os.environ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]
creds = urllib.request.urlopen(url).read().decode()
print(creds)
```

The response contains an `AccessKeyId`, `SecretAccessKey`, and `Token` for the task role. This role has `s3:GetObject` and `secretsmanager:GetSecretValue` permissions. The attacker has escalated from CI/CD reconnaissance to full data access by pivoting through the container layer.

### Defender's Side: CloudTrail Query 2

`ecs:ExecuteCommand` from a non-human identity is a critical alert. Even a single event warrants investigation.

```sql
SELECT
    useridentity.arn AS actor_arn,
    eventtime,
    json_extract_scalar(requestparameters, '$.cluster') AS ecs_cluster,
    json_extract_scalar(requestparameters, '$.command') AS executed_command,
    json_extract_scalar(requestparameters, '$.interactive') AS interactive
FROM cloudtrail_logs
WHERE
    eventsource = 'ecs.amazonaws.com'
    AND eventname = 'ExecuteCommand'
ORDER BY eventtime;
```

`interactive=true` from a CI/CD service account ARN is high-confidence suspicious. Unless your org has explicitly scoped break-glass automation that calls `ExecuteCommand`, treat this as an attacker in your container.

The remediation: deny `ecs:ExecuteCommand` by default. Allow it only for specific roles (on-call responders) with MFA conditions. Disable `enableExecuteCommand` on production ECS services. If you need it for debugging, enable it temporarily and log all sessions to CloudWatch.

### S3 and Secrets Manager Exfiltration

With the task role credentials, the attacker downloads everything:

- A customer database export CSV from S3 (contains the S3 exfil flag)
- A Terraform state backup file from S3 (contains credentials and a bonus flag)
- Production API keys from Secrets Manager (Stripe, SendGrid, GitHub PAT, database URL)

### Defender's Side: CloudTrail Queries 3 and 4

Bulk `GetSecretValue` calls across multiple secrets in rapid succession are a dead giveaway. Legitimate applications read 1-2 secrets at startup.

```sql
SELECT
    useridentity.arn AS actor_arn,
    eventtime,
    json_extract_scalar(requestparameters, '$.secretId') AS secret_id
FROM cloudtrail_logs
WHERE
    eventsource = 'secretsmanager.amazonaws.com'
    AND eventname IN ('ListSecrets', 'GetSecretValue')
ORDER BY useridentity.arn, eventtime;
```

Detection rule: alert when a single actor calls `GetSecretValue` on 3+ distinct secrets within 60 seconds, or calls `ListSecrets` followed by `GetSecretValue` (the automated exfil pattern).

For S3, flag any actor that calls `ListBuckets` followed by `GetObject` on 5+ distinct objects within 5 minutes. Cross-reference the source IP against known application subnets. CI/CD service accounts calling `GetObject` on data buckets is a policy misconfiguration that enables this attack.

One caveat: `s3:GetObject` is a data event, not a management event. CloudTrail does not log it by default. The lab's Terraform enables S3 object-level data events on the trail, which is why Query 4 works here. In your own environment, you need to explicitly enable data event logging for S3 buckets you want to monitor. Without it, the exfiltration is invisible.

For Secrets Manager: `GetSecretValue` API calls are logged in CloudTrail, but the actual secret values are not included in the log. You see who called it, when, and which secret, but not what they read.

## The Full Chain in CloudTrail

Query 5 in the lab's detection pack correlates all four phases into a single timeline, classified by attack phase:

```
0-CREDENTIAL-VALIDATION  → sts:GetCallerIdentity
1-RECON                  → ListUsers, ListRoles, ListClusters, DescribeTasks
2-PIVOT                  → ecs:ExecuteCommand
3-EXFIL-SECRETS          → secretsmanager:GetSecretValue
4-EXFIL-S3               → s3:GetObject
```

Run this query against your own CloudTrail after completing the lab. You get the full attack timeline: every API call, timestamped, with source IP and user agent. That is the same reconstruction a SOC analyst would build during an actual incident.

## What Would Have Stopped This

Five controls. Any one of them breaks the chain.

**1. Pin GitHub Actions to commit SHAs.** The tag poisoning worked because consumers used `@v1`. A force-push to a tag silently changes what every consumer executes. Pin to the full SHA.

**2. Remove `pull_request_target` or isolate its secrets.** Replace with `pull_request` for any job that executes fork code. If `pull_request_target` is required, never pass secrets to steps that process untrusted input.

**3. Scope CI/CD IAM roles to minimum permissions.** The stolen credentials could enumerate every service in the account. A CI/CD role that can call `ListUsers`, `ListSecrets`, and `DescribeTasks` is giving attackers a free map of your infrastructure.

**4. Deny `ecs:ExecuteCommand` for CI/CD roles.** This is the single change that breaks the pivot. Without ECS Exec access, the attacker has reconnaissance but no data.

**5. Separate sensitive data from CI/CD-accessible resources.** Customer exports and Terraform state files should not live in buckets that CI/CD roles can enumerate. State files belong in a dedicated state account with strict access controls.

## Running the Lab

```bash
git clone https://github.com/raajheshkannaa/teampcp-goat.git
cd teampcp-goat
make preflight    # Check tools and environment
make deploy       # Deploy AWS infrastructure (~$1-2)
```

Module 1 runs locally with `act` (no AWS needed for the CI/CD exercises). Module 2 requires the deployed infrastructure. The full kill chain takes about 49 minutes. Six flags total. `make destroy` when done.

The lab includes Claude Code slash commands for interactive guided mode (`/project:start`) and a writeup template (`docs/writeup-template.md`) for documenting your experience as a portfolio piece.

## Sources

- [Wiz CIRT: Tracking TeamPCP Post-Compromise Activity](https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild)
- [Aqua Security: Trivy Supply Chain Attack Advisory (CVE-2026-33634)](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)
- [SANS: When the Security Scanner Became the Weapon](https://www.sans.org/blog/when-security-scanner-became-weapon-inside-teampcp-supply-chain-campaign)
- [CERT-EU: European Commission Breach Attribution](https://therecord.media/european-commission-cyberattack-teampcp)
- [GitHub Security Lab: Preventing PwnRequests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
