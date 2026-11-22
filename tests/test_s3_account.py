import importlib.util
from pathlib import Path
from unittest.mock import patch

import boto3
from botocore.stub import Stubber


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / relative_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load_module(
    "s3_account_collector",
    "src/collectors/s3_account_collector.py",
)

detector = load_module(
    "s3_account_detector",
    "src/detectors/s3_account_detector.py",
)


def make_clients():
    credentials = {
        "region_name": "us-east-1",
        "aws_access_key_id": "testing",
        "aws_secret_access_key": "testing",
    }

    return (
        boto3.client("sts", **credentials),
        boto3.client("s3control", **credentials),
    )


def run_stubbed_assessment(sts, s3control):
    original_client = boto3.client

    def client_factory(service_name, **kwargs):
        if service_name == "sts":
            return sts
        if service_name == "s3control":
            return s3control
        return original_client(service_name, **kwargs)

    with patch.object(
        collector.boto3, "client", side_effect=client_factory
    ):
        return collector.assess_account_s3_public_access()


def add_identity_response(stubber):
    stubber.add_response(
        "get_caller_identity",
        {
            "UserId": "TESTUSER",
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
        },
        {},
    )


def test_account_protection_enabled():
    sts, s3control = make_clients()

    with Stubber(sts) as sts_stub, Stubber(s3control) as s3_stub:
        add_identity_response(sts_stub)

        s3_stub.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    setting: True
                    for setting in collector.SETTINGS
                }
            },
            {"AccountId": "123456789012"},
        )

        result = run_stubbed_assessment(sts, s3control)

    assert result["status"] == "PASS"
    assert detector.evaluate_account_s3_findings(result) == []


def test_account_protection_missing():
    sts, s3control = make_clients()

    with Stubber(sts) as sts_stub, Stubber(s3control) as s3_stub:
        add_identity_response(sts_stub)

        s3_stub.add_client_error(
            "get_public_access_block",
            service_error_code="NoSuchPublicAccessBlockConfiguration",
            expected_params={"AccountId": "123456789012"},
        )

        result = run_stubbed_assessment(sts, s3control)

    assert result["status"] == "FAIL"

    findings = detector.evaluate_account_s3_findings(result)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "S3-ACCOUNT-001"
    assert findings[0]["status"] == "OPEN"


def test_account_protection_incomplete():
    sts, s3control = make_clients()

    with Stubber(sts) as sts_stub, Stubber(s3control) as s3_stub:
        add_identity_response(sts_stub)

        settings = {
            setting: True for setting in collector.SETTINGS
        }
        settings["RestrictPublicBuckets"] = False

        s3_stub.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": settings
            },
            {"AccountId": "123456789012"},
        )

        result = run_stubbed_assessment(sts, s3control)

    assert result["status"] == "FAIL"
    assert result["settings"]["RestrictPublicBuckets"] is False

    findings = detector.evaluate_account_s3_findings(result)
    assert findings[0]["severity"] == "HIGH"


def test_account_access_denied():
    sts, s3control = make_clients()

    with Stubber(sts) as sts_stub, Stubber(s3control) as s3_stub:
        add_identity_response(sts_stub)

        s3_stub.add_client_error(
            "get_public_access_block",
            service_error_code="AccessDenied",
            expected_params={"AccountId": "123456789012"},
        )

        result = run_stubbed_assessment(sts, s3control)

    assert result["status"] == "ERROR"
    assert result["error_code"] == "AccessDenied"

    findings = detector.evaluate_account_s3_findings(result)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "S3-ACCOUNT-002"
    assert findings[0]["status"] == "REVIEW"
