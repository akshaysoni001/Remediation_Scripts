# Remediation_Scripts

# Details of Use Cases & Required Commands to execute remediation script.

# Unauthorized Api Calls

Use Case :\
Ensure a log metric filter and alarm exist for unauthorized API calls (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/unauthorized_api.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","unauthorized_api_metric_filter_alarm_exists":"False"}'


# Aws Config Configuration Changes
Use Case: \
Ensure a log metric filter and alarm exist for AWS Config configuration changes (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/aws_config_configuration_changes.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","config_configuration_changes_metric_filter_alarm_exists":"False"}'

# Aws Organization Changes
Use Case: \
Ensure a log metric filter and alarm exists for AWS Organizations changes (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/aws_organization_changes.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","aws_organization_changes_metric_filter_alarm_exists":"False"}'


# CloudTrail Configuration Changes
Use Case: \
Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/cloudtrail_configuration_changes.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","cloudtrail_configuration_changes_metric_filter_alarm_exists":"False"}'

# Disable/Delete Customer Managed KMS Keys
Use Case: \
4.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/disable_delete_kms_key.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","delete_kms_activity_metric_filter_alarm_exists":"False"}'

# IAM Policy Changes
Use Case: \
Ensure a log metric filter and alarm exist for IAM policy changes (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/IAM_Policy_Changes.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","iam_policy_changes_metric_filter_alarm_exists":"False"}'

# Aws Management Console Auth Failure

Use Case:\
Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/Mangement_console_auth_failure.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","console_sign_failure_metric_filter_alarm_exists":"False"}'

# Console Sign In Without MFA
Use Case:\
Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/signin_without_mfa.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","signin_without_mfa_metric_filter_alarm_exists":"False"}'

# Root Account Usage Alert
Use Case:\
Ensure a log metric filter and alarm exist for usage of 'root' account (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/root_account_signin.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","root_account_signin_usage_metric_filter_alarm_exists":"False"}'

# S3 Bucket Policy Changes
Use Case:\
Ensure a log metric filter and alarm exist for S3 bucket policy changes (Automated)

**Ansible Command** \
ansible-playbook remediation/ansible/aws/scripts/s3_bucket_policy_change.yml --extra-vars '{"aws_account_id":"aws_account_id","aws_access_key":"access_key","aws_secret_key":"secret_key", "aws_region":"us-east-1","s3_bucket_policy_change_metric_filter_alarm_exists":"False"}'
