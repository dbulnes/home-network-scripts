#!/bin/bash
python3 -m venv runtime-env
source runtime-env/bin/activate
pip install boto3 requests
