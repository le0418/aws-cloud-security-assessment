import boto3
from botocore.exceptions import ClientError


def assess_s3_buckets():
    s3 = boto3.client("s3")
    results = []

    response = s3.list_buckets()

    for bucket in response.get("Buckets", []):
        name = bucket["Name"]

        finding = {
            "bucket": name,
            "public_access_block": "UNKNOWN",
            "default_encryption": "UNKNOWN",
        }

        try:
            pab = s3.get_public_access_block(
                Bucket=name
            )["PublicAccessBlockConfiguration"]

            finding["public_access_block"] = (
                "PASS" if all(
                    pab.get(setting, False)
                    for setting in [
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    ]
                ) else "FAIL"
            )

        except ClientError as error:
            code = error.response["Error"]["Code"]

            if code == "NoSuchPublicAccessBlockConfiguration":
                finding["public_access_block"] = "FAIL"
            else:
                finding["public_access_block"] = f"ERROR: {code}"

        try:
            s3.get_bucket_encryption(Bucket=name)
            finding["default_encryption"] = "PASS"

        except ClientError as error:
            code = error.response["Error"]["Code"]

            if code in [
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchServerSideEncryptionConfiguration",
            ]:
                finding["default_encryption"] = "REVIEW"
            else:
                finding["default_encryption"] = f"ERROR: {code}"

        results.append(finding)

    return results


if __name__ == "__main__":
    import json

    findings = assess_s3_buckets()

    print(json.dumps(findings, indent=2))
