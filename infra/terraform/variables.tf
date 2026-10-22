variable "role_name" {
  description = "Name of the IAM role for CloudSentinel read-only auditor"
  type        = string
  default     = "CloudSentinelReadOnlyAuditorRole"
}

variable "trusted_principal_arn" {
  description = "The ARN of the AWS IAM user or role authorized to assume this auditor role (e.g., arn:aws:iam::123456789012:root)"
  type        = string
}

variable "external_id" {
  description = "Optional external ID condition to prevent the confused deputy problem"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Resource tags to assign to the IAM role and policy"
  type        = map(string)
  default = {
    Project     = "CloudSentinel"
    Environment = "Audit"
    ManagedBy   = "Terraform"
  }
}
