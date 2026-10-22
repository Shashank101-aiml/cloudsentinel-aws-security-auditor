import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import Optional
from app.core.logging import logger

# Bounded retry configuration with jitter and exponential backoff
BOTO_CONFIG = Config(
    retries={
        "max_attempts": 3,
        "mode": "adaptive",
    },
    connect_timeout=5,
    read_timeout=15,
)


class AWSClientFactory:
    """Creates boto3 client sessions following least-privilege and read-only practices."""

    @staticmethod
    def get_session(profile: Optional[str] = None) -> boto3.Session:
        """Creates a boto3 Session using either an explicit profile or the default SDK credential chain."""
        try:
            if profile:
                logger.info(f"Creating AWS session with profile: {profile}")
                return boto3.Session(profile_name=profile)
            return boto3.Session()
        except Exception as e:
            logger.error(f"Failed to create boto3 Session: {str(e)}")
            raise

    @staticmethod
    def get_client(
        service_name: str,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        assume_role_arn: Optional[str] = None,
    ):
        """
        Instantiates a read-only client for a specific AWS service.
        Supports role assumption if assume_role_arn is specified.
        """
        session = AWSClientFactory.get_session(profile=profile)

        if assume_role_arn:
            sts_client = session.client("sts", region_name=region, config=BOTO_CONFIG)
            try:
                assumed_role_object = sts_client.assume_role(
                    RoleArn=assume_role_arn,
                    RoleSessionName="CloudSentinelReadOnlyAuditSession",
                    DurationSeconds=3600,
                )
                credentials = assumed_role_object["Credentials"]
                return boto3.client(
                    service_name,
                    region_name=region,
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                    config=BOTO_CONFIG,
                )
            except ClientError as e:
                logger.error(f"Failed to assume role {assume_role_arn}: {e.response['Error']['Message']}")
                raise

        return session.client(service_name, region_name=region, config=BOTO_CONFIG)
