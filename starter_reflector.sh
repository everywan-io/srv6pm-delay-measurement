#!/bin/bash

# Variables
GRPC_STUBS_PATH="./srv6_delay_measurement/commons/protos/srv6pm/gen-py"
VENV_ACTIVATE_SCRIPT="./.venv/bin/activate"
REFLECTOR_FILENAME="./srv6_delay_measurement/reflector.py"

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
python ${REFLECTOR_FILENAME}

# Deactivate virtual environment
deactivate
