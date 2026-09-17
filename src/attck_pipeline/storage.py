from __future__ import annotations

from dataclasses import dataclass

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from loguru import logger

from attck_pipeline.config import Settings


@dataclass
class StoredObject:
    bucket: str
    key: str
    sha256: str
    size: int
    version_id: str | None = None


class S3Storage:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.client = boto3.client(
            "s3",
            endpoint_url=self.settings.s3_endpoint_url,
            aws_access_key_id=self.settings.s3_access_key,
            aws_secret_access_key=self.settings.s3_secret_key,
            region_name=self.settings.s3_region,
            config=BotoConfig(signature_version="s3v4"),
        )

    def ensure_buckets(self) -> None:
        for bucket in (self.settings.s3_bucket_bundles, self.settings.s3_bucket_reports):
            try:
                self.client.head_bucket(Bucket=bucket)
            except ClientError:
                self.client.create_bucket(Bucket=bucket)
                if self.settings.s3_enable_object_lock:
                    try:
                        self.client.put_object_lock_configuration(
                            Bucket=bucket,
                            ObjectLockConfiguration={
                                "ObjectLockEnabled": "Enabled",
                                "Rule": {
                                    "DefaultRetention": {
                                        "Mode": "COMPLIANCE",
                                        "Years": self.settings.retention_years,
                                    }
                                },
                            },
                        )
                    except ClientError as e:
                        logger.warning(f"Object Lock not available for {bucket}: {e}")
                logger.info(f"Created bucket: {bucket}")

    def put_bundle(self, domain: str, version: str, raw_bytes: bytes, sha256: str) -> StoredObject:
        bucket = self.settings.s3_bucket_bundles
        key = f"{domain}/{version}/{sha256}.json"

        if self._exists(bucket, key):
            logger.info(f"Bundle already stored: {key}")
            return StoredObject(bucket=bucket, key=key, sha256=sha256, size=len(raw_bytes))

        self.client.put_object(
            Bucket=bucket,
            Key=key,
            Body=raw_bytes,
            ContentType="application/json",
            Metadata={"sha256": sha256, "domain": domain, "version": version},
        )

        logger.info(f"Stored bundle: s3://{bucket}/{key} ({len(raw_bytes)} bytes)")
        return StoredObject(bucket=bucket, key=key, sha256=sha256, size=len(raw_bytes))

    def get_bundle(self, domain: str, version: str, sha256: str) -> bytes:
        bucket = self.settings.s3_bucket_bundles
        key = f"{domain}/{version}/{sha256}.json"
        response = self.client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    def put_report(self, report_id: str, payload_bytes: bytes, sha256: str, fmt: str = "json") -> StoredObject:
        bucket = self.settings.s3_bucket_reports
        year = report_id.split("-")[1] if "-" in report_id else "unknown"
        ext = fmt
        key = f"{year}/{report_id}.{ext}"

        self.client.put_object(
            Bucket=bucket,
            Key=key,
            Body=payload_bytes,
            ContentType=self._content_type(fmt),
            Metadata={"sha256": sha256, "report_id": report_id},
        )

        logger.info(f"Stored report: s3://{bucket}/{key} ({len(payload_bytes)} bytes)")
        return StoredObject(bucket=bucket, key=key, sha256=sha256, size=len(payload_bytes))

    def get_report(self, report_id: str, fmt: str = "json") -> bytes:
        bucket = self.settings.s3_bucket_reports
        year = report_id.split("-")[1] if "-" in report_id else "unknown"
        key = f"{year}/{report_id}.{fmt}"
        response = self.client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    def put_overlay_snapshot(self, snapshot_id: str, payload_bytes: bytes, sha256: str) -> StoredObject:
        bucket = self.settings.s3_bucket_bundles
        key = f"overlay-snapshots/{snapshot_id}.json"

        self.client.put_object(
            Bucket=bucket,
            Key=key,
            Body=payload_bytes,
            ContentType="application/json",
            Metadata={"sha256": sha256},
        )

        logger.info(f"Stored overlay snapshot: s3://{bucket}/{key}")
        return StoredObject(bucket=bucket, key=key, sha256=sha256, size=len(payload_bytes))

    def _exists(self, bucket: str, key: str) -> bool:
        try:
            self.client.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError:
            return False

    @staticmethod
    def _content_type(fmt: str) -> str:
        return {
            "json": "application/json",
            "html": "text/html",
            "pdf": "application/pdf",
        }.get(fmt, "application/octet-stream")

    def blob_ref(self, bucket: str, key: str) -> str:
        return f"s3://{bucket}/{key}"
