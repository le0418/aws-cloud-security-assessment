def evaluate_s3_findings(bucket_results):
    findings = []

    for bucket in bucket_results:
        bucket_name = bucket["bucket"]
        status = bucket["public_access_block"]

        if status == "FAIL":
            findings.append({
                "finding_id": "S3-001",
                "resource_type": "AWS::S3::Bucket",
                "resource": bucket_name,
                "severity": "HIGH",
                "status": "OPEN",
                "title": "S3 bucket lacks complete bucket-level public access blocking",
                "description": (
                    "One or more bucket-level S3 Block Public Access "
                    "settings are not enabled."
                ),
                "recommendation": (
                    "Enable all four bucket-level S3 Block Public "
                    "Access settings after reviewing application "
                    "requirements."
                ),
                "control_mapping": [
                    "NIST 800-53 AC-3",
                    "NIST 800-53 AC-6"
                ]
            })

        elif status.startswith("ERROR:") or status == "UNKNOWN":
            findings.append({
                "finding_id": "S3-002",
                "resource_type": "AWS::S3::Bucket",
                "resource": bucket_name,
                "severity": "MEDIUM",
                "status": "REVIEW",
                "title": "S3 public access configuration could not be verified",
                "description": (
                    "The assessment could not establish the "
                    "bucket-level public access block configuration."
                ),
                "recommendation": (
                    "Review AWS permissions and retry the assessment."
                ),
                "control_mapping": [
                    "NIST 800-53 CA-7"
                ]
            })

    return findings
