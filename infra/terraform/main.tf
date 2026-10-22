terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Trust Policy document for AssumeRole
data "aws_iam_policy_document" "assume_role_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.trusted_principal_arn]
    }

    dynamic "condition" {
      for_each = var.external_id != "" ? [1] : []
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [var.external_id]
      }
    }
  }
}

# IAM Role
resource "aws_iam_role" "auditor_role" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.assume_role_trust.json
  max_session_duration = 3600
  tags                 = var.tags
}

# Least-Privilege Read-Only Policy Document
data "aws_iam_policy_document" "auditor_policy_doc" {
  statement {
    sid    = "CloudSentinelSecurityAuditPermissions"
    effect = "Allow"
    actions = [
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
    ]
    resources = ["*"]
  }
}

# IAM Policy Resource
resource "aws_iam_policy" "auditor_policy" {
  name        = "${var.role_name}-Policy"
  description = "Narrow read-only policy for CloudSentinel cloud security audit inspection"
  policy      = data.aws_iam_policy_document.auditor_policy_doc.json
  tags        = var.tags
}

# Policy Attachment
resource "aws_iam_role_policy_attachment" "auditor_attach" {
  role       = aws_iam_role.auditor_role.name
  policy_arn = aws_iam_policy.auditor_policy.arn
}
