def evaluate_account_s3_findings(result):
    status = result["status"]

    if status == "PASS":
        return []

    if status == "FAIL":
        return [{
            "finding_id": "S3-ACCOUNT-001",
            "resource_type": "AWS::Account",
            "resource": "AWS_ACCOUNT",
            "severity": "HIGH",
            "status": "OPEN",
            "title": "Account-level S3 Block Public Access incomplete",
            "description": (
                "One or more account-level S3 Block Public Access "
                "settings are not enabled."
            ),
            "recommendation": (
                "Review public-access dependencies and enable all "
                "four account-level Block Public Access settings."
            ),
            "control_mapping": [
                "NIST 800-53 AC-3",
                "NIST 800-53 AC-6"
            ]
        }]

    return [{
        "finding_id": "S3-ACCOUNT-002",
        "resource_type": "AWS::Account",
        "resource": "AWS_ACCOUNT",
        "severity": "MEDIUM",
        "status": "REVIEW",
        "title": "Account-level S3 protection could not be verified",
        "description": (
            "The assessment could not determine account-level "
            "S3 Block Public Access configuration."
        ),
        "recommendation": (
            "Review AWS permissions and retry the assessment."
        ),
        "control_mapping": [
            "NIST 800-53 CA-7"
        ]
    }]
