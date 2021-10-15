#!/bin/bash

# Variables
GRPC_STUBS_PATH="./commons/protos/srv6pm/gen-py"
VENV_ACTIVATE_SCRIPT="./.venv/bin/activate"
SENDER_FILENAME="./sender.py"

# Require root
if [ "$EUID" -ne 0 ]
  then echo "Sender must run as root"
  exit
fi

# Add the path to the gRPC stubs
export PYTHONPATH="${PYTHONPATH}:${GRPC_STUBS_PATH}"

# Activate virtual environment
source ${VENV_ACTIVATE_SCRIPT}

# Start the sender
python ${SENDER_FILENAME}

# Deactivate virtual environment
deactivate