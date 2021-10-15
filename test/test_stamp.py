#!/usr/bin/python

##########################################################################
# Copyright (C) 2021 Carmine Scarpitta - (University of Rome "Tor Vergata")
# www.uniroma2.it/netgroup
#
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# STAMP Test library
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
STAMP Test library.
"""

import sys
sys.path.append('.')   # TODO sistemare meglio

import logging
import time

from controller import Controller

# Configure logging
logging.basicConfig(level=logging.DEBUG) # TODO sistemare


if __name__ == '__main__':
    controller = Controller()
    controller.add_stamp_sender(
        node_id='r1',
        grpc_ip='fcfd:0:0:1::1',
        grpc_port=12345,
        ip='fcff:1::1',
        udp_port=50051
    )
    controller.add_stamp_reflector(
        node_id='r8',
        grpc_ip='fcfd:0:0:8::1',
        grpc_port=12345,
        ip='fcff:8::1',
        udp_port=50052
    )

    controller.init_sender(node_id='r1')
    controller.init_reflector(node_id='r8')

    ssid = controller.create_stamp_session(
        sender_id='r1', reflector_id='r8', sidlist=['fcff:4::1', 'fcff:8::1'],
        return_sidlist=['fcff:4::1', 'fcff:1::1'], interval=5, auth_mode=None,
        key_chain=None, timestamp_format=None,
        packet_loss_type=None,
        delay_measurement_mode=None,
        session_reflector_mode=None
    )

    controller.start_stamp_session(ssid)

    time.sleep(10)

    for i in range(0, 10):
        controller.get_stamp_results(ssid)
        time.sleep(10)

    controller.stop_stamp_session(ssid)

    controller.destroy_stamp_session(ssid)

    controller.reset_stamp_sender('r1')
    controller.reset_stamp_reflector('r8')

