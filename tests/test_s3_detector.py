import importlib.util
from pathlib import Path


DETECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "detectors"
    / "s3_detector.py"
)

spec = importlib.util.spec_from_file_location(
    "s3_detector", DETECTOR_PATH
)
detector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detector)


def test_missing_public_access_block_generates_finding():
    results = [{
        "bucket": "test-review-bucket",
        "public_access_block": "FAIL",
        "default_encryption": "PASS"
    }]

    findings = detector.evaluate_s3_findings(results)

    assert len(findings) == 1
    assert findings[0]["finding_id"] == "S3-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["status"] == "OPEN"


def test_secure_bucket_generates_no_finding():
    results = [{
        "bucket": "test-secure-bucket",
        "public_access_block": "PASS",
        "default_encryption": "PASS"
    }]

    findings = detector.evaluate_s3_findings(results)

    assert findings == []


def test_permission_error_generates_review_finding():
    results = [{
        "bucket": "test-unknown-bucket",
        "public_access_block": "ERROR: AccessDenied",
        "default_encryption": "UNKNOWN"
    }]

    findings = detector.evaluate_s3_findings(results)

    assert len(findings) == 1
    assert findings[0]["finding_id"] == "S3-002"
    assert findings[0]["status"] == "REVIEW"
