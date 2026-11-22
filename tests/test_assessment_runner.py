import importlib.util
import json
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "src" / "reporting" / "assessment_runner.py"

spec = importlib.util.spec_from_file_location(
    "assessment_runner", RUNNER_PATH
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_secure_environment_generates_clean_report(tmp_path):
    account_result = {
        "scope": "AWS_ACCOUNT",
        "control": "S3_ACCOUNT_PUBLIC_ACCESS_BLOCK",
        "status": "PASS",
        "settings": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }

    bucket_results = [{
        "bucket": "test-secure-bucket",
        "public_access_block": "PASS",
        "default_encryption": "PASS",
    }]

    with (
        patch.object(runner, "PROJECT_ROOT", tmp_path),
        patch.object(
            runner,
            "assess_account_s3_public_access",
            return_value=account_result,
        ),
        patch.object(
            runner,
            "assess_s3_buckets",
            return_value=bucket_results,
        ),
    ):
        report = runner.run_assessment()

    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["buckets_assessed"] == 1
    assert report["summary"]["account_public_access_block"] == "PASS"

    report_path = tmp_path / "reports" / "aws_s3_assessment.json"
    assert report_path.exists()

    saved_report = json.loads(
        report_path.read_text(encoding="utf-8")
    )
    assert saved_report["summary"] == report["summary"]


def test_insecure_environment_generates_findings(tmp_path):
    account_result = {
        "scope": "AWS_ACCOUNT",
        "control": "S3_ACCOUNT_PUBLIC_ACCESS_BLOCK",
        "status": "FAIL",
        "settings": {},
    }

    bucket_results = [{
        "bucket": "test-incomplete-bucket",
        "public_access_block": "FAIL",
        "default_encryption": "PASS",
    }]

    with (
        patch.object(runner, "PROJECT_ROOT", tmp_path),
        patch.object(
            runner,
            "assess_account_s3_public_access",
            return_value=account_result,
        ),
        patch.object(
            runner,
            "assess_s3_buckets",
            return_value=bucket_results,
        ),
    ):
        report = runner.run_assessment()

    assert report["summary"]["total_findings"] == 2
    assert report["summary"]["high"] == 2
    assert report["summary"]["open"] == 2

    finding_ids = {
        finding["finding_id"]
        for finding in report["findings"]
    }

    assert finding_ids == {
        "S3-ACCOUNT-001",
        "S3-001",
    }

    report_path = tmp_path / "reports" / "aws_s3_assessment.json"
    assert report_path.exists()


def test_permission_error_generates_review_finding(tmp_path):
    account_result = {
        "scope": "AWS_ACCOUNT",
        "control": "S3_ACCOUNT_PUBLIC_ACCESS_BLOCK",
        "status": "ERROR",
        "error_code": "AccessDenied",
        "settings": {},
    }

    with (
        patch.object(runner, "PROJECT_ROOT", tmp_path),
        patch.object(
            runner,
            "assess_account_s3_public_access",
            return_value=account_result,
        ),
        patch.object(
            runner,
            "assess_s3_buckets",
            return_value=[],
        ),
    ):
        report = runner.run_assessment()

    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["medium"] == 1
    assert report["summary"]["review"] == 1
    assert report["findings"][0]["finding_id"] == "S3-ACCOUNT-002"
