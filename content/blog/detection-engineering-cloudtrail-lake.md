# Detection Engineering with CloudTrail Lake at Scale

*March 2026*

Most teams doing CloudTrail detections are still using EventBridge pattern matching. You match on `StopLogging` or `ConsoleLogin` without MFA, fire an SNS notification, and call it a day.

That works for single-event detections. It completely falls apart when an attacker chains actions across multiple accounts over hours — stolen access key used from a new IP, `PutUserPolicy` to escalate, S3 bucket policy changed to public, snapshot modified for exfiltration. EventBridge sees each event in isolation. Your SOC gets 40+ individual alerts and doesn't connect them.

I built a detection pipeline on CloudTrail Lake across 300+ AWS accounts that solves this. Here's how it works and why I chose this approach over the traditional CloudWatch/S3/Athena stack.

## Why CloudTrail Lake

Previously, to do detections at scale meant enabling CloudTrail in all accounts & regions, shipping logs to S3, setting up Glue crawlers & Athena partitions, and scheduling queries. Multiple moving parts.

CloudTrail Lake simplifies all of this — you toggle a couple switches in the Organization Account, it collects cloudtrail logs from all accounts & regions, normalizes them, and you query with SQL. That's it.

The tradeoff is you lose real-time alerting. CloudTrail Lake queries take a few seconds to run, and I poll on a 10-minute schedule. For detections that need sub-second response, keep EventBridge. For anything requiring cross-account correlation, historical lookback, or multi-event logic — CloudTrail Lake.

## Architecture

```
    AWS Organization Account
    ┌─────────────────────────┐
    │  CloudTrail Lake        │
    │  (Org-wide Event Store) │
    └───────────┬─────────────┘
                │ cross-account role assumption
    Security/Automation Account
    ┌───────────┴─────────────┐
    │  EventBridge (10 min)   │
    │       │                 │
    │  Lambda functions (VPC) │
    │       │                 │
    │     Slack               │
    └─────────────────────────┘
```

Each detection is a Lambda function deployed via CDK. EventBridge triggers them every 10 minutes. The Lambda assumes a hub role into the automation account, then into the org account to query CloudTrail Lake. Results get parsed, evaluated, and sent to Slack.

The Lambdas run in a VPC with NAT — the reason for this is CloudTrail Lake API calls go over the internet, and running in a private subnet gives you VPC Flow Logs on the detection infrastructure itself. Monitoring your monitors.

## Detection 1: Resource Made Public

This catches the most real incidents. Across 10+ AWS services, resources can be made internet-accessible through policy changes.

```sql
SELECT eventTime, recipientAccountId, awsRegion, eventJson, eventName
FROM <event_data_store>
WHERE eventName IN (
    'PutBucketPolicy',           -- S3
    'SetRepositoryPolicy',       -- ECR
    'CreateElasticsearchDomain', -- OpenSearch
    'UpdateElasticsearchDomainConfig',
    'CreateKey', 'PutKeyPolicy', -- KMS
    'SetVaultAccessPolicy',      -- Glacier
    'SetQueueAttributes',        -- SQS
    'CreateTopic',               -- SNS
    'SetTopicAttributes',
    'PutResourcePolicy'          -- SecretsManager
)
AND eventTime > '<start>' AND eventTime < '<end>'
```

The tricky part — each service embeds resource policies differently in CloudTrail events. S3 uses `requestParameters.bucketPolicy`, ECR uses `requestParameters.policyText`, KMS uses `requestParameters.policy`. The Lambda parses each service's format and evaluates using `policyuniverse`:

```python
from policyuniverse.policy import Policy

def policy_is_internet_accessible(json_policy):
    if json_policy is None:
        return False
    return Policy(json_policy).is_internet_accessible()
```

An EventBridge rule can tell you "someone called `PutBucketPolicy`." It cannot tell you whether the resulting policy actually grants public access. This detection can.

## Detection 2: Compromised Access Keys

When AWS detects an access key exposed on GitHub, it applies a quarantine policy called `AWSExposedCredentialPolicy_DO_NOT_REMOVE` via `PutUserPolicy`. Many teams don't monitor for this.

```sql
SELECT eventTime, recipientAccountId, eventJson
FROM <event_data_store>
WHERE eventName = 'PutUserPolicy'
AND eventTime > '<start>' AND eventTime < '<end>'
```

```python
if event.get("eventName") == "PutUserPolicy" \
    and request_params.get("policyName") == "AWSExposedCredentialPolicy_DO_NOT_REMOVE":
    # An access key in your org was just flagged as compromised
    alert(user_arn, access_key_id, account_id)
```

The reason CloudTrail Lake is better here — after this fires, you can immediately run a follow-up query: "what did this access key do across all accounts in the last 24 hours?" Historical lookback that's impossible with EventBridge.

## Detection 3: Security Config Tampering

The "covering their tracks" detection. Attackers disable logging & monitoring before proceeding.

```sql
SELECT eventTime, recipientAccountId, eventJson, eventName
FROM <event_data_store>
WHERE eventName IN (
    'DeleteAccountPublicAccessBlock',
    'DeleteDeliveryChannel',
    'DeleteDetector',
    'DeleteFlowLogs',
    'DeleteTrail',
    'DisableEbsEncryptionByDefault',
    'StopConfigurationRecorder',
    'StopLogging'
)
AND eventTime > '<start>' AND eventTime < '<end>'
```

At 300+ accounts, you need an allowlist or you'll drown in noise from legitimate automation:

```python
ALLOW_LIST = [
    "OrganizationAccountAccessRole",
    "AWSControlTowerExecution",
]

if user not in ALLOW_LIST:
    alert(f"Sensitive API call {event_name} by {user} in account {account_id}")
```

Start with a narrow allowlist. Expand it only when you confirm false positives. Never the other way around.

## Detection 4: Public Snapshots & AMIs

EC2 snapshots and AMIs contain disk images — credentials, application code, database backups. Making them public is a data exfiltration vector.

```sql
SELECT eventTime, recipientAccountId, eventJson
FROM <event_data_store>
WHERE eventName IN ('ModifySnapshotAttribute', 'ModifyImageAttribute')
AND eventTime > '<start>' AND eventTime < '<end>'
```

For snapshots, check if `createVolumePermission` added the `all` group. For AMIs, check if `launchPermission` added `group: all`. These are high-fidelity — there's almost never a legitimate reason to make a snapshot or AMI public in an enterprise environment.

## Detection 5: CodeBuild Project Visibility

One that gets missed — CodeBuild projects can be set to `PUBLIC_READ`, making build logs visible to anyone. Build logs frequently contain env vars, IAM creds, and internal URLs.

```sql
SELECT eventTime, recipientAccountId, eventJson
FROM <event_data_store>
WHERE eventName = 'UpdateProjectVisibility'
AND eventTime > '<start>' AND eventTime < '<end>'
```

```python
if deep_get(event, "requestParameters", "projectVisibility") == "PUBLIC_READ":
    alert(project_arn, user_arn, account_id, region)
```

## The 10-Minute Window

EventBridge triggers each Lambda every 10 minutes. The SQL looks back 20 minutes:

```python
delta = datetime.now(timezone.utc) - timedelta(minutes=20)
```

The reason for the overlap — CloudTrail Lake event ingestion isn't instant. Events arrive with a delay of several minutes. The 20-minute window ensures nothing falls through the gap between runs. Deduplication happens at the Slack notification level.

## When NOT to Use CloudTrail Lake

| Detection | Use This | Why |
|---|---|---|
| Root login, `StopLogging` | EventBridge | Single event, needs sub-minute alerting |
| Resource made public (multi-service) | CloudTrail Lake | Needs policy evaluation, not just pattern match |
| GuardDuty/Config findings | SecurityHub + EventBridge | Already aggregated |
| Cross-account privilege escalation | CloudTrail Lake | Needs cross-account & temporal correlation |

Don't move everything to CloudTrail Lake. Use the right tool for each detection.

## Getting Started

The entire pipeline — CDK stack, all Lambda detections, EventBridge configuration — is open source:

[github.com/raajheshkannaa/aws-cloudtrail-lake-detections](https://github.com/raajheshkannaa/aws-cloudtrail-lake-detections)

All you need is an Organization-wide CloudTrail Lake event data store and an automation account with cross-account role access (see [fleet-access](https://github.com/raajheshkannaa/fleet-access) for the IAM foundation).

Its honestly satisfying watching these detections fire across hundreds of accounts with so minimal effort compared to the old S3 & Athena approach. If you're running a multi-account AWS setup and still relying purely on EventBridge pattern matching, you're missing things.

---

*All detection code is available at [github.com/raajheshkannaa/aws-cloudtrail-lake-detections](https://github.com/raajheshkannaa/aws-cloudtrail-lake-detections). The IAM role foundation is at [fleet-access](https://github.com/raajheshkannaa/fleet-access).*

---

*Raajhesh Kannaa Chidambaram — Cloud Security Engineer. I build security automation at scale. More at [defensive.works](https://defensive.works) and [github.com/raajheshkannaa](https://github.com/raajheshkannaa).*
