from contextlib import asynccontextmanager
from typing import AsyncIterator

import aioboto3

from app.config import settings

_session = aioboto3.Session()


@asynccontextmanager
async def get_table():
    kwargs = {"region_name": settings.aws_region}
    if settings.dynamodb_endpoint:
        kwargs["endpoint_url"] = settings.dynamodb_endpoint

    async with _session.resource("dynamodb", **kwargs) as dynamo:
        table = await dynamo.Table(settings.dynamodb_table)
        yield table


@asynccontextmanager
async def get_s3() -> AsyncIterator:
    kwargs = {"region_name": settings.aws_region}
    if settings.dynamodb_endpoint:  # reuse local endpoint for S3 too
        kwargs["endpoint_url"] = settings.dynamodb_endpoint

    async with _session.client("s3", **kwargs) as s3:
        yield s3


async def ensure_table():
    """Create the DynamoDB table if it doesn't exist (for local dev).

    In production (no dynamodb_endpoint), the table is provisioned by CDK.
    """
    if not settings.dynamodb_endpoint:
        return  # CDK-managed table, skip creation

    kwargs = {"region_name": settings.aws_region}
    kwargs["endpoint_url"] = settings.dynamodb_endpoint

    async with _session.client("dynamodb", **kwargs) as client:
        tables = (await client.list_tables())["TableNames"]
        if settings.dynamodb_table in tables:
            return

        await client.create_table(
            TableName=settings.dynamodb_table,
            KeySchema=[
                {"AttributeName": "domain", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "domain", "KeyType": "HASH"},
                {"AttributeName": "entry_type", "KeyType": "RANGE"},
            ]
            if False
            else [{"AttributeName": "domain", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
