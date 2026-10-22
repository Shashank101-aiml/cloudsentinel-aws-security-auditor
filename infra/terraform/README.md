# CloudSentinel Least-Privilege IAM Auditor Role (Terraform)

This Terraform module creates a narrowly scoped, read-only IAM role and policy that enables CloudSentinel to inspect configuration posture across supported AWS services (S3, IAM, EC2, RDS, and CloudTrail) without administrative privileges and without the ability to modify, delete, or create resources.

---

## Prerequisites

- [Terraform CLI](https://developer.hashicorp.com/terraform/downloads) (>= 1.5.0)
- AWS CLI configured with administrative or IAM delegation privileges in the target AWS account

---

## Setup Instructions

1. **Navigate to the Terraform directory:**
   ```bash
   cd infra/terraform
   ```

2. **Configure input variables:**
   Copy the example variables file:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```
   Edit `terraform.tfvars` and set `trusted_principal_arn` to the ARN of the IAM user, role, or AWS account that will run the audit.

3. **Initialize Terraform:**
   ```bash
   terraform init
   ```

4. **Review the execution plan:**
   ```bash
   terraform plan
   ```
   Verify that Terraform will only create:
   - 1 IAM Role (`aws_iam_role.auditor_role`)
   - 1 IAM Policy (`aws_iam_policy.auditor_policy`)
   - 1 Policy Attachment (`aws_iam_role_policy_attachment.auditor_attach`)

5. **Apply the configuration:**
   ```bash
   terraform apply
   ```

6. **Note the Output Role ARN:**
   The output `auditor_role_arn` will be displayed:
   ```
   Outputs:
   auditor_role_arn = "arn:aws:iam::123456789012:role/CloudSentinelReadOnlyAuditorRole"
   ```
   You can provide this ARN in the CloudSentinel UI or in `.env` (`AWS_ASSUME_ROLE_ARN`).

---

## Teardown / Cleanup Instructions

To completely remove the auditor role and policy when no longer needed:

```bash
terraform destroy
```
Review the destroy plan and confirm with `yes`.
