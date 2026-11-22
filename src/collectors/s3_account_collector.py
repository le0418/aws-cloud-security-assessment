import boto3
from botocore.exceptions import ClientError


SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def assess_account_s3_public_access():
    sts = boto3.client("sts")
    s3control = boto3.client("s3control", region_name="us-east-1")

    account_id = sts.get_caller_identity()["Account"]

    try:
        response = s3control.get_public_access_block(
            AccountId=account_id
        )

        configuration = response["PublicAccessBlockConfiguration"]

        return {
            "scope": "AWS_ACCOUNT",
            "control": "S3_ACCOUNT_PUBLIC_ACCESS_BLOCK",
            "status": (
                "PASS"
                if all(configuration.get(setting) is True for setting in SETTINGS)
                else "FAIL"
            ),
            "settings": {
                setting: configuration.get(setting, False)
                for setting in SETTINGS
            },
        }

    except ClientError as error:
        code = error.response["Error"]["Code"]

        if code == "NoSuchPublicAccessBlockConfiguration":
            return {
                "scope": "AWS_ACCOUNT",
                "control": "S3_ACCOUNT_PUBLIC_ACCESS_BLOCK",
                "status": "FAIL",
                "settings": {},
            }

        return {
            "scope": "AWS_ACCOUNT",
            "control": "S3_ACCOUNT_PUBLIC_ACCESS_BLOCK",
            "status": "ERROR",
            "error_code": code,
            "settings": {},
        }


if __name__ == "__main__":
    import json

    print(json.dumps(assess_account_s3_public_access(), indent=2))
