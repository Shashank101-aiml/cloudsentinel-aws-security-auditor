# AWS Connection & Setup Guide

This guide explains how to safely connect CloudSentinel to an AWS environment using read-only credentials.

---

## 1. Supported Authentication Methods

CloudSentinel supports three standard AWS credential mechanisms in order of precedence:

1. **Explicit AWS CLI Profile**:
   Configured in `~/.aws/credentials` and `~/.aws/config`. You can select the profile name directly in the CloudSentinel UI or via the `AWS_PROFILE` environment variable.
2. **Standard AWS SDK Provider Chain**:
   Standard environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) or instance profile metadata (IAM role attached to EC2 or ECS task).
3. **Assumed IAM Role**:
   An IAM role ARN specified in the UI or in `.env` (`AWS_ASSUME_ROLE_ARN`). The backend calls `sts:AssumeRole` using temporary short-lived credentials (1 hour duration).

> [!IMPORTANT]
> CloudSentinel **never** prompts for or stores raw AWS access keys or secrets in the browser, in the database, or in logs.

---

## 2. Least-Privilege IAM Policy

To run real AWS audits, attach the following read-only policy to your IAM user or role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudSentinelReadOnlyAuditorPolicy",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3control:GetPublicAccessBlock",
        "iam:GetAccountSummary",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances",
        "rds:DescribeDBInstances",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 3. Pre-Flight Verification

Before launching a real scan:
1. Open the **AWS Connection** tab in the dashboard.
2. Verify that STS caller identity successfully resolves your Account ID and ARN.
3. If credentials are not present, CloudSentinel operates in **Demo Mode**, displaying deterministic sample resources.
