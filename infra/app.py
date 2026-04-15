#!/usr/bin/env python3
"""CDK entry point for 24Defend infrastructure."""

import os
import sys

import aws_cdk as cdk

from config import ENVIRONMENTS
from stack import DefendStack

app = cdk.App()

env_name = os.environ.get("DEFEND_ENV", "dev")
if env_name not in ENVIRONMENTS:
    print(f"Error: DEFEND_ENV='{env_name}' not found. Valid: {list(ENVIRONMENTS.keys())}")
    sys.exit(1)

env_config = ENVIRONMENTS[env_name]

DefendStack(
    app,
    f"defend-{env_name}",
    env_name=env_name,
    env_config=env_config,
    env=cdk.Environment(
        account=env_config["account"],
        region=env_config["region"],
    ),
)

app.synth()
