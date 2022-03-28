#!/bin/bash

# Variables
GRPC_STUBS_PATH="./srv6_delay_measurement/commons/protos/srv6pm/gen-py"
VENV_ACTIVATE_SCRIPT="./.venv/bin/activate"
#SENDER_FILENAME="./srv6_delay_measurement/sender.py"
SENDER_MODULE_NAME="srv6_delay_measurement.sender"

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
#python ${SENDER_FILENAME}
python ${SENDER_MODULE_NAME}

# Deactivate virtual environment
deactivate