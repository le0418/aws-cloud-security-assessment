# AWS S3 Security Assessment and Remediation

## Project Overview

Developed a Python-based AWS S3 security assessment workflow using
Boto3, automated detection logic, structured findings, and Terraform.

This project was completed in a controlled personal AWS lab.

## Security Controls Assessed

- Account-level S3 Block Public Access
- Bucket-level S3 Block Public Access
- S3 default encryption configuration
- AWS API access and permission-error handling

The implementation assesses selected S3 controls only.
It is not a comprehensive AWS security or compliance audit.

## Detection

A deliberately incomplete bucket-level Block Public Access
configuration was provisioned for testing.

The assessment detected:

- Finding ID: S3-001
- Severity: HIGH
- Status: OPEN
- Finding: Incomplete bucket-level public access blocking
- Referenced NIST SP 800-53 controls: AC-3 and AC-6

The configuration finding did not establish that the bucket
was publicly accessible.

Account-level Block Public Access protections remained enabled.

## Remediation

Updated the Terraform configuration to enable all four
bucket-level Block Public Access settings:

- BlockPublicAcls
- IgnorePublicAcls
- BlockPublicPolicy
- RestrictPublicBuckets

Applied the change through Terraform and independently verified
the configuration using AWS CLI.

## Assessment Results

| Metric | Before | After |
|---|---:|---:|
| S3 buckets assessed | 2 | 2 |
| Total findings | 1 | 0 |
| HIGH findings | 1 | 0 |
| OPEN findings | 1 | 0 |
| Account-level Block Public Access | PASS | PASS |

Finding S3-001 was no longer detected after remediation.

Zero findings means no findings within the implemented
assessment scope; it does not establish comprehensive compliance.

## Automated Testing

Executed 13 Python unit tests covering:

- Secure and insecure configurations
- Account-level security controls
- Bucket-level security controls
- Security finding generation
- Permission-error handling
- Assessment report generation

Final result: 13 passed.

## Infrastructure Teardown

Terraform successfully destroyed all three temporary resources:

- S3 test bucket
- Bucket-level Block Public Access configuration
- Bucket encryption configuration

Verified that:

- Terraform state contained no remaining resources
- The temporary S3 bucket was removed
- The preexisting AWS SAM bucket remained present
- All four account-level Block Public Access settings remained enabled

## Technologies

Python, Boto3, AWS CLI, Amazon S3, Terraform,
pytest, Git, GitHub, Windows PowerShell.

## Security and Evidence Handling

Raw AWS assessment reports, Terraform state, saved plans,
and unredacted evidence are excluded from the public repository.

The public documentation contains sanitized results from
the controlled lab exercise.
