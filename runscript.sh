#!/bin/bash

set -x

source runtime-env/bin/activate

python cloudflare-ddns.py
