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
# Implementation of a SDN Controller CLI
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
Implementation of a SDN Controller CLI.
"""


import argparse
import logging
import pprint

from srv6_delay_measurement import nb_controller_api


# Default command-line arguments
DEFAULT_GRPC_IP = '::'
DEFAULT_GRPC_PORT = 54321

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
    datefmt='%m-%d %H:%M')

# Get the root logger
logger = logging.getLogger()


class InvalidArgument(Exception):

    def __init__(self, arg=None):
        self.msg = ''
        if arg is not None:
            self.msg = f'Mandatory argument is missing: {arg}'
        super().__init__(self.msg)


def register_sender(controller_ip, controller_port, node_id, grpc_ip,
                    grpc_port, ip, udp_port=None, node_name=None,
                    interfaces=None, stamp_source_ipv6_address=None,
                    initialize=True):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.register_stamp_sender(
        node_id=node_id,
        grpc_ip=grpc_ip,
        grpc_port=grpc_port,
        ip=ip,
        udp_port=udp_port,
        node_name=node_name,
        interfaces=interfaces,
        stamp_source_ipv6_address=stamp_source_ipv6_address,  # optional
        initialize=initialize
    )


def register_reflector(controller_ip, controller_port, node_id, grpc_ip,
                       grpc_port, ip, udp_port, node_name=None,
                       interfaces=None, stamp_source_ipv6_address=None,
                       initialize=True):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.register_stamp_reflector(
        node_id=node_id,
        grpc_ip=grpc_ip,
        grpc_port=grpc_port,
        ip=ip,
        udp_port=udp_port,
        node_name=node_name,
        interfaces=interfaces,
        stamp_source_ipv6_address=stamp_source_ipv6_address,  # optional
        initialize=initialize
    )


def unregister_node(controller_ip, controller_port, node_id):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.unregister_stamp_node(node_id=node_id)


def init_node(controller_ip, controller_port, node_id):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.init_stamp_node(node_id=node_id)


def reset_node(controller_ip, controller_port, node_id):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.reset_stamp_node(node_id=node_id)


def create_session(controller_ip, controller_port, sender_id,
                   reflector_id=None, direct_sidlist=None,
                   return_sidlist=None, interval=None, auth_mode=None,
                   key_chain=None, timestamp_format=None,
                   packet_loss_type=None,
                   delay_measurement_mode=None,
                   session_reflector_mode=None,
                   sender_source_ip=None,
                   reflector_source_ip=None, description=None,
                   duration=0):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.create_stamp_session(
        sender_id=sender_id, reflector_id=reflector_id,
        direct_sidlist=direct_sidlist,
        return_sidlist=return_sidlist, interval=interval,
        auth_mode=auth_mode, key_chain=key_chain,
        timestamp_format=timestamp_format,
        packet_loss_type=packet_loss_type,
        delay_measurement_mode=delay_measurement_mode,
        session_reflector_mode=session_reflector_mode,
        description=description,
        sender_source_ip=sender_source_ip,
        reflector_source_ip=reflector_source_ip,
        duration=duration
    )


def start_session(controller_ip, controller_port, ssid):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.start_stamp_session(ssid=ssid)


def stop_session(controller_ip, controller_port, ssid):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.stop_stamp_session(ssid=ssid)


def destroy_session(controller_ip, controller_port, ssid):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    nb_interface.destroy_stamp_session(ssid=ssid)


def get_results(controller_ip, controller_port, ssid):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    pprint.pprint(nb_interface.get_stamp_results(ssid=ssid), indent=2)


def get_sessions(controller_ip, controller_port, ssid):

    nb_interface = nb_controller_api.NorthboundInterface(
        server_ip=controller_ip,
        server_port=controller_port
    )

    pprint.pprint(nb_interface.get_stamp_sessions(ssid=ssid), indent=2)


def raise_exception_if_param_is_none(param, value):
    if value is None:
        raise InvalidArgument(param)


def raise_exception_on_mandatory_param_omitted(operation, args):
    if operation == 'register-sender':
        raise_exception_if_param_is_none('--node-id', args.node_id)
        raise_exception_if_param_is_none('--node-grpc-ip', args.node_grpc_ip)
        raise_exception_if_param_is_none(
            '--node-grpc-port', args.node_grpc_port)
        raise_exception_if_param_is_none('--node-ip', args.node_ip)
    elif operation == 'register-reflector':
        raise_exception_if_param_is_none('--node-id', args.node_id)
        raise_exception_if_param_is_none('--node-grpc-ip', args.node_grpc_ip)
        raise_exception_if_param_is_none(
            '--node-grpc-port', args.node_grpc_port)
        raise_exception_if_param_is_none('--node-ip', args.node_ip)
        raise_exception_if_param_is_none('--udp-port', args.udp_port)
    elif operation == 'unregister-node':
        raise_exception_if_param_is_none('--node-id', args.node_id)
    elif operation == 'init-node':
        raise_exception_if_param_is_none('--node-id', args.node_id)
    elif operation == 'reset-node':
        raise_exception_if_param_is_none('--node-id', args.node_id)
    elif operation == 'create-session':
        raise_exception_if_param_is_none('--sender-id', args.sender_id)
        raise_exception_if_param_is_none('--reflector-id', args.reflector_id)
    elif operation == 'start-session':
        raise_exception_if_param_is_none('--ssid', args.ssid)
    elif operation == 'stop-session':
        raise_exception_if_param_is_none('--ssid', args.ssid)
    elif operation == 'destroy-session':
        raise_exception_if_param_is_none('--ssid', args.ssid)
    elif operation == 'get-results':
        raise_exception_if_param_is_none('--ssid', args.ssid)
    elif operation == 'get-sessions':
        pass


def dispatch_operation(operation, args):
    raise_exception_on_mandatory_param_omitted(operation, args)

    if operation == 'register-sender':
        return register_sender(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            node_id=args.node_id,
            grpc_ip=args.node_grpc_ip,
            grpc_port=args.node_grpc_port,
            ip=args.node_ip,
            udp_port=args.udp_port,
            interfaces=args.interfaces,
            stamp_source_ipv6_address=args.node_source_ip,
            initialize=args.initialize_node,
            tenantid=args.tenantid)
    if operation == 'register-reflector':
        return register_reflector(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            node_id=args.node_id,
            grpc_ip=args.node_grpc_ip,
            grpc_port=args.node_grpc_port,
            ip=args.node_ip,
            udp_port=args.udp_port,
            interfaces=args.interfaces,
            stamp_source_ipv6_address=args.node_source_ip,
            initialize=args.initialize_node,
            tenantid=args.tenantid)
    if operation == 'unregister-node':
        return unregister_node(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            node_id=args.node_id,
            tenantid=args.tenantid)
    if operation == 'init-node':
        return init_node(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            node_id=args.node_id,
            tenantid=args.tenantid)
    if operation == 'reset-node':
        return reset_node(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            node_id=args.node_id,
            tenantid=args.tenantid)
    if operation == 'create-session':
        return create_session(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            sender_id=args.sender_id,
            reflector_id=args.reflector_id,
            direct_sidlist=args.direct_sidlist,
            return_sidlist=args.return_sidlist,
            interval=args.interval,
            auth_mode=args.auth_mode,
            key_chain=args.key_chain,
            timestamp_format=args.timestamp_format,
            packet_loss_type=args.packet_loss_type,
            delay_measurement_mode=args.delay_measurement_mode,
            session_reflector_mode=args.session_reflector_mode,
            sender_source_ip=args.sender_source_ip,
            reflector_source_ip=args.reflector_source_ip,
            description=args.session_description,
            duration=args.duration,
            tenantid=args.tenantid
        )
    if operation == 'start-session':
        return start_session(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            ssid=args.ssid,
            tenantid=args.tenantid)
    if operation == 'stop-session':
        return stop_session(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            ssid=args.ssid,
            tenantid=args.tenantid)
    if operation == 'destroy-session':
        return destroy_session(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            ssid=args.ssid,
            tenantid=args.tenantid)
    if operation == 'get-results':
        return get_results(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            ssid=args.ssid,
            tenantid=args.tenantid)
    if operation == 'get-sessions':
        return get_sessions(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            ssid=args.ssid,
            tenantid=args.tenantid)


def parse_arguments():
    """
    This function parses the command-line arguments.

    Returns
    -------
    None.
    """

    parser = argparse.ArgumentParser(
        description='SDN Controller CLI.')
    parser.add_argument('--controller-ip', dest='controller_ip', type=str,
                        help='IP address of the SDN Controller',
                        default=DEFAULT_GRPC_IP)
    parser.add_argument('--controller-port', dest='controller_port', type=int,
                        default=DEFAULT_GRPC_PORT,
                        help='gRPC port of the controller (default: 54321)')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        default=False, help='Debug mode (default: False)')

    parser.add_argument('--operation', dest='operation', required=True,
                        choices=['register-sender', 'register-reflector',
                                 'unregister-node', 'init-node', 'reset-node',
                                 'create-session', 'start-session',
                                 'stop-session', 'destroy-session',
                                 'get-results', 'get-sessions'],
                        help='gRPC port of the controller (default: 54321)')

    parser.add_argument('--node-id', dest='node_id', type=str,
                        help='Node ID')
    parser.add_argument('--node-grpc-ip', dest='node_grpc_ip', type=str,
                        help='gRPC IP of the STAMP node to register')
    parser.add_argument('--node-grpc-port', dest='node_grpc_port', type=int,
                        help='gRPC port of the STAMP node to register')
    parser.add_argument('--node-ip', dest='node_ip', type=str,
                        help='IP address of the STAMP node')
    parser.add_argument('--udp-port', dest='udp_port', type=int,
                        help='UDP port used for STAMP')
    parser.add_argument('--interfaces', dest='interfaces', nargs='+',
                        help='Interfaces on which STAMP should be listen '
                        'for STAMP packets')
    parser.add_argument('--node-source-ip', dest='node_source_ip', type=str,
                        help='IPv6 address to be used as source for the '
                        'STAMP packets')
    parser.add_argument('--initialize-node', dest='initialize_node',
                        action='store_true', help='Define whether to '
                        'automatically initialize the STAMP node after its '
                        'creation')
    parser.add_argument('--duration', dest='duration', type=int,
                        help='Duration of the STAMP Session', default=0)

    parser.add_argument('--ssid', dest='ssid', type=int,
                        help='STAMP Session Identifier (SSID)')
    parser.add_argument('--session-description', dest='session_description',
                        type=str, help='A description for the STAMP Session '
                        'to be created')
    parser.add_argument('--sender-id', dest='sender_id', type=str,
                        help='ID of the STAMP Sender to be used for the '
                        'STAMP Session')
    parser.add_argument('--reflector-id', dest='reflector_id', type=str,
                        help='ID of the STAMP Reflector to be used for the '
                        'STAMP Session')
    parser.add_argument('--direct-sidlist', dest='direct_sidlist',  nargs='+',
                        help='Segment list of the direct path to test')
    parser.add_argument('--return-sidlist', dest='return_sidlist', nargs='+',
                        help='Segment list of the return path to test')
    parser.add_argument('--interval', dest='interval', type=int,
                        help='Interval (in seconds) between two STAMP packets')
    parser.add_argument('--auth-mode', dest='auth_mode', type=str,
                        help='Authentication Mode')
    parser.add_argument('--key-chain', dest='key_chain', type=str,
                        help='Key chain')
    parser.add_argument('--timestamp-format', dest='timestamp_format',
                        type=str, help='Timestamp Format')
    parser.add_argument('--packet-loss-type', dest='packet_loss_type',
                        type=str, help='Packet Loss Type')
    parser.add_argument('--delay-measurement-mode',
                        dest='delay_measurement_mode', type=str,
                        help='Delay Measurement Mode')
    parser.add_argument('--session-reflector-mode',
                        dest='session_reflector_mode', type=str,
                        help='Session Reflector Mode')
    parser.add_argument('--sender-source-ip', dest='sender_source_ip',
                        type=str, help='IP address to be used as source of '
                        'the STAMP packets')
    parser.add_argument('--reflector-source-ip', dest='reflector_source_ip',
                        type=str, help='IP address to be used as source of '
                        'the STAMP packets')
    parser.add_argument('--tenant-id', dest='tenantid', default=None,
                        type=str, help='ID of the tenant')

    args = parser.parse_args()

    return args


def __main():

    # Parse and extract command-line arguments
    logger.debug('Parsing arguments')
    args = parse_arguments()
    debug = args.debug

    # Configure logging
    if debug:
        logger.setLevel(level=logging.DEBUG)
    else:
        logger.setLevel(level=logging.INFO)

    # Run the gRPC server and block forever
    logger.debug('Invoking requested operation: %s', args.operation)

    try:
        dispatch_operation(args.operation, args)
        logger.info('Operation completed (OK)')
    except Exception as err:
        logger.error(f'Error - {err}')


if __name__ == '__main__':
    __main()
