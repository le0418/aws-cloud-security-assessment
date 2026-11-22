import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from collectors.s3_collector import assess_s3_buckets
from collectors.s3_account_collector import assess_account_s3_public_access
from detectors.s3_detector import evaluate_s3_findings
from detectors.s3_account_detector import evaluate_account_s3_findings


def run_assessment():
    print("=== AWS CLOUD SECURITY ASSESSMENT ===")

    print("Assessing account-level S3 protection...")
    account_result = assess_account_s3_public_access()

    print("Assessing bucket-level S3 protection...")
    bucket_results = assess_s3_buckets()

    findings = (
        evaluate_account_s3_findings(account_result)
        + evaluate_s3_findings(bucket_results)
    )

    summary = {
        "account_public_access_block": account_result["status"],
        "buckets_assessed": len(bucket_results),
        "total_findings": len(findings),
        "high": sum(
            f["severity"] == "HIGH" for f in findings
        ),
        "medium": sum(
            f["severity"] == "MEDIUM" for f in findings
        ),
        "open": sum(
            f["status"] == "OPEN" for f in findings
        ),
        "review": sum(
            f["status"] == "REVIEW" for f in findings
        ),
    }

    report = {
        "assessment_type": "AWS_S3_SECURITY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "account_results": account_result,
        "bucket_results": bucket_results,
        "findings": findings,
    }

    report_dir = PROJECT_ROOT / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / "aws_s3_assessment.json"

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n=== ASSESSMENT SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print(f"\nReport saved locally: {report_path}")

    return report


if __name__ == "__main__":
    run_assessment()
