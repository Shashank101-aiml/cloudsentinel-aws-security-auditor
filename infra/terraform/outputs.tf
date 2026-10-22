output "auditor_role_arn" {
  description = "The ARN of the read-only CloudSentinel IAM role"
  value       = aws_iam_role.auditor_role.arn
}

output "auditor_policy_arn" {
  description = "The ARN of the attached read-only IAM policy"
  value       = aws_iam_policy.auditor_policy.arn
}
