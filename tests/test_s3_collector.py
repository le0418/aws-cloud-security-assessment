import importlib.util
from pathlib import Path
from unittest.mock import patch

import boto3
from botocore.stub import Stubber


COLLECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "collectors"
    / "s3_collector.py"
)

spec = importlib.util.spec_from_file_location(
    "s3_collector", COLLECTOR_PATH
)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def test_no_buckets():
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )

    with Stubber(client) as stubber:
        stubber.add_response(
            "list_buckets",
            {"Buckets": []},
            {},
        )

        with patch.object(
            collector.boto3,
            "client",
            return_value=client,
        ):
            assert collector.assess_s3_buckets() == []


def test_secure_bucket():
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )

    with Stubber(client) as stubber:
        stubber.add_response(
            "list_buckets",
            {
                "Buckets": [
                    {"Name": "test-secure-bucket"}
                ]
            },
            {},
        )

        stubber.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            {"Bucket": "test-secure-bucket"},
        )

        stubber.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            },
            {"Bucket": "test-secure-bucket"},
        )

        with patch.object(
            collector.boto3,
            "client",
            return_value=client,
        ):
            results = collector.assess_s3_buckets()

    assert len(results) == 1
    assert results[0]["public_access_block"] == "PASS"
    assert results[0]["default_encryption"] == "PASS"


def test_missing_public_access_block():
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )

    with Stubber(client) as stubber:
        stubber.add_response(
            "list_buckets",
            {
                "Buckets": [
                    {"Name": "test-review-bucket"}
                ]
            },
            {},
        )

        stubber.add_client_error(
            "get_public_access_block",
            service_error_code=(
                "NoSuchPublicAccessBlockConfiguration"
            ),
            expected_params={
                "Bucket": "test-review-bucket"
            },
        )

        stubber.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            },
            {"Bucket": "test-review-bucket"},
        )

        with patch.object(
            collector.boto3,
            "client",
            return_value=client,
        ):
            results = collector.assess_s3_buckets()

    assert results[0]["public_access_block"] == "FAIL"
    assert results[0]["default_encryption"] == "PASS"
