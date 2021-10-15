#!/bin/bash

# Variables
GRPC_STUBS_PATH="./commons/protos/srv6pm/gen-py"
VENV_ACTIVATE_SCRIPT="./.venv/bin/activate"
REFLECTOR_FILENAME="./test/test_stamp.py"

# Add the path to the gRPC stubs
export PYTHONPATH="${PYTHONPATH}:${GRPC_STUBS_PATH}"

# Activate virtual environment
source ${VENV_ACTIVATE_SCRIPT}

# Start the reflector
python ${REFLECTOR_FILENAME}

# Deactivate virtual environment
deactivate