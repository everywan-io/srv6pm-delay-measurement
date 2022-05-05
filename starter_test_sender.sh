#!/bin/bash

# Variables
GRPC_STUBS_PATH="./srv6_delay_measurement/commons/protos/srv6pm/gen-py"
VENV_ACTIVATE_SCRIPT="./.venv/bin/activate"
SENDER_TEST_MODULE_NAME="srv6_delay_measurement.test.test_sender"

# Require root
if [ "$EUID" -ne 0 ]
  then echo "Reflector must run as root"
  exit
fi

# Add the path to the gRPC stubs
export PYTHONPATH="${PYTHONPATH}:${GRPC_STUBS_PATH}"

# Activate virtual environment
source ${VENV_ACTIVATE_SCRIPT}

# Start the reflector
python -m ${SENDER_TEST_MODULE_NAME}

# Deactivate virtual environment
deactivate
