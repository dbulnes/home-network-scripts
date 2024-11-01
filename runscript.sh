#!/bin/bash

set -x

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Activate virtual environment using absolute path
source "${SCRIPT_DIR}/runtime-env/bin/activate"

# Run python script using absolute path
python "${SCRIPT_DIR}/cloudflare-ddns.py"
