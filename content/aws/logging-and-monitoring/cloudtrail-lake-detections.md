## CloudTrail Lake Threat Detections

Threat detection rules built on AWS CloudTrail Lake — SQL-based queries across your entire AWS Organization, with Lambda-based alerting to Slack.

For the full deep-dive on why CloudTrail Lake over EventBridge, the architecture, and all 5 detection patterns, read the blog post: **[Detection Engineering with CloudTrail Lake at Scale](../../blog/detection-engineering-cloudtrail-lake.md)**

## Detections

```
- ami_modified_for_public_image
- resource_made_public
- snapshot_made_public
- key_compromised
- security_configuration_change
- codebuild_made_public
- cloudtrail_stopped
- add_admin_permissions
```

## Source

- GitHub: [aws-cloudtrail-lake-detections](https://github.com/raajheshkannaa/aws-cloudtrail-lake-detections)
- Prerequisite: [fleet-access](https://github.com/raajheshkannaa/fleet-access) (cross-account IAM role structure)

*Note*: Detection logic forked from [Panther Labs CloudTrail Rules](https://github.com/panther-labs/panther-analysis/tree/master/aws_cloudtrail_rules), adapted for CloudTrail Lake.
