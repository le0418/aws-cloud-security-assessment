# AWS Cloud Security Assessment & Compliance Automation

A Python-based AWS security assessment project that collects
AWS configuration data, evaluates security controls, and
generates structured JSON findings.

## Current Capabilities

- Account-level S3 Block Public Access assessment
- Bucket-level S3 Block Public Access assessment
- Bucket default-encryption configuration inspection
- Security finding classification and remediation guidance
- Consolidated JSON assessment reporting
- Automated unit and integration tests

## Technology Stack

- Python 3
- Boto3 / AWS SDK
- AWS CLI
- pytest
- Git
- Terraform (planned infrastructure testing)

## Architecture

AWS Account
    |
    +-- Account-Level S3 Collector
    |
    +-- Bucket-Level S3 Collector
              |
              v
       Security Detectors
              |
              v
       Consolidated Report
              |
              v
       Local JSON Output

## Running the Assessment

Install dependencies in a Python virtual environment:

    python -m pip install boto3 pytest

Configure AWS credentials using an authorized AWS profile
or another supported AWS credential provider.

Run:

    python src/reporting/assessment_runner.py

The assessment currently reads AWS configurations and
does not modify AWS resources.

## Automated Testing

Run:

    python -m pytest tests -v

Current verified baseline: 13 passing tests.

Tests use mocked AWS responses and temporary directories.

## Security Considerations

- Never commit AWS credentials or Terraform state.
- Raw assessment reports are excluded from Git.
- Assessment output may contain AWS resource identifiers.
- Missing bucket-level Block Public Access settings do
  not necessarily indicate actual public exposure.
- A missing explicit bucket encryption configuration
  does not imply objects are unencrypted.
- Findings are preliminary policy assessments, not
  complete compliance determinations.

## Project Status

Completed:
- S3 security collectors and detectors
- Consolidated reporting
- Automated testing
- Live AWS configuration assessment
- Verified account-level S3 hardening exercise

Planned:
- Terraform-managed test infrastructure
- Controlled configuration-gap detection
- Remediation and reassessment
- Additional AWS security services
- Cross-account assessment

## Disclaimer

This is an independently developed security engineering
portfolio project. It is not a production-certified
security assessment platform.
