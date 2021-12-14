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
# Implementation of a SDN Controller capable of controlling STAMP Sessions
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
Implementation of a SDN Controller capable of controlling STAMP Sessions.
"""

from .libs.libstamp import (
    AuthenticationMode,
    DelayMeasurementMode,
    PacketLossType,
    SessionReflectorMode,
    TimestampFormat
)


import sys
from pkg_resources import resource_filename
sys.path.append(resource_filename(__name__, 'commons/protos/srv6pm/gen_py/'))

from .utils import get_address_family
from .utils import grpc_to_py_resolve_defaults, py_to_grpc
from .controller_utils import STAMPNode, STAMPSession, compute_packet_delay
import stamp_sender_pb2_grpc
import stamp_sender_pb2
import stamp_reflector_pb2_grpc
import stamp_reflector_pb2
from .exceptions import (
    CreateSTAMPSessionError,
    DestroySTAMPSessionError,
    GetSTAMPResultsError,
    InitSTAMPNodeError,
    InvalidStampNodeError,
    NodeIdAlreadyExistsError,
    NodeIdNotFoundError,
    NodeInitializedError,
    NodeNotInitializedError,
    NotAStampReflectorError,
    NotAStampSenderError, ResetSTAMPNodeError,
    STAMPSessionNotFoundError,
    STAMPSessionNotRunningError,
    STAMPSessionRunningError,
    StartSTAMPSessionError,
    StopSTAMPSessionError,
    STAMPSessionsExistError)

import controller_pb2_grpc
import controller_pb2
import common_pb2
from concurrent import futures
from threading import Thread
from socket import AF_INET, AF_INET6
import argparse
import logging
import time

import grpc



# Default command-line arguments
DEFAULT_GRPC_IP = None
DEFAULT_GRPC_PORT = 54321

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
    datefmt='%m-%d %H:%M')

# Get the root logger
logger = logging.getLogger()


def get_grpc_channel_sender(ip, port):
    """
    Open an insecure gRPC channel towards the Sender and return the stub
     and the channel.

    Parameters
    ----------
    ip : str
        IP address of the STAMP Sender.
    port : int
        UDP port of the STAMP Sender

    Returns
    -------
    channel : grpc._channel.Channel
        gRPC channel to the Sender.
    stub : stamp_sender_pb2_grpc.STAMPSessionSenderServiceStub
        Stub used to interact with the Sender.
    """

    # Open the channel
    logger.debug('Creating a gRPC Channel to STAMP Sender (IP %s, port %d)',
                 ip, port)
    # Get the address of the server
    addr_family = get_address_family(ip)
    if addr_family == AF_INET6:
        server_address = f'ipv6:[{ip}]:{port}'
    elif addr_family == AF_INET:
        server_address = f'ipv4:{ip}:{port}'
    else:
        logging.error('Invalid address: %s' % ip)
        return
    channel = grpc.insecure_channel(server_address)
    # Get the stub
    stub = stamp_sender_pb2_grpc.STAMPSessionSenderServiceStub(channel)

    # Return
    return channel, stub


def get_grpc_channel_reflector(ip, port):
    """
    Open an insecure gRPC channel towards the Reflector and return the stub
     and the channel.

    Parameters
    ----------
    ip : str
        IP address of the STAMP Reflector.
    port : int
        UDP port of the STAMP Reflector

    Returns
    -------
    channel : grpc._channel.Channel
        gRPC channel to the Reflector.
    stub : stamp_reflector_pb2_grpc.STAMPSessionReflectorServiceStub
        Stub used to interact with the Reflector.
    """

    # Open the channel
    logger.debug('Creating a gRPC Channel to STAMP Reflector '
                 '(IP %s, port %d)', ip, port)
    # Get the address of the server
    addr_family = get_address_family(ip)
    if addr_family == AF_INET6:
        server_address = f'ipv6:[{ip}]:{port}'
    elif addr_family == AF_INET:
        server_address = f'ipv4:{ip}:{port}'
    else:
        logging.error('Invalid address: %s' % ip)
        return
    channel = grpc.insecure_channel(server_address)
    # Get the stub
    stub = stamp_reflector_pb2_grpc.STAMPSessionReflectorServiceStub(channel)

    # Return
    return channel, stub


class Controller:
    """
    A class to represent a SDN Controller to control the STAMP nodes.

    Attributes
    ----------
    last_ssid : int
        Last used STAMP Session Identifier (SSID)
    reusable_ssid : set
        Pool of SSIDs allocated to STAMP Sessions terminated, available to be
         reused for other STAMP Sessions
    stamp_nodes : dict
        Map the node identifier to the STAMPNode instanc
    stamp_sessions : dict
        Map the SSID to the corresponding STAMPSession object
    debug : bool
        Whether to enable or not debug mode.

    Methods
    -------
    add_stamp_sender(node_id, grpc_ip, grpc_port, ip, udp_port=None,
                     node_name=None, interfaces=None,
                     stamp_source_ipv6_address=None, initialize=True)
        Add a STAMP Sender to the Controller inventory.
    add_stamp_reflector(node_id, grpc_ip, grpc_port, ip, udp_port,
                        node_name=None, interfaces=None,
                        stamp_source_ipv6_address=None, initialize=True)
        Add a STAMP Reflector to the Controller inventory.
    init_sender(sender_udp_port=20000, interfaces=None)
        Establish a gRPC connection to a STAMP Session Sender and initialize
         it.
    init_reflector(reflector_udp_port=20001, interfaces=None)
        Establish a gRPC connection to a STAMP Session Reflector and
         initialize it.
    reset_stamp_sender()
        Reset a STAMP Sender and tear down the gRPC
         connection.
    reset_stamp_reflector()
        Reset a STAMP Reflector and tear down the gRPC
         connection.
    _create_stamp_sender_session(ssid, sender, reflector=None,
                                 sidlist=[], interval=10, auth_mode=None,
                                 key_chain=None, timestamp_format=None,
                                 packet_loss_type=None,
                                 delay_measurement_mode=None)
        Internal function used to create a STAMP Session on the STAMP Sender.
         You should not use this function. Instead, you should use
         create_stamp_session.
    _create_stamp_reflector_session(ssid, sender, reflector=None,
                                    sidlist=[], interval=10, auth_mode=None,
                                    key_chain=None, timestamp_format=None,
                                    packet_loss_type=None,
                                    delay_measurement_mode=None)
        Internal function used to create a STAMP Session on the STAMP
         Reflector. You should not use this function. Instead, you should use
         create_stamp_session.
    create_stamp_session(sender, reflector=None, sidlist=[],
                         return_sidlist=[], interval=10, auth_mode=None,
                         key_chain=None, timestamp_format=None,
                         packet_loss_type=None, delay_measurement_mode=None,
                         session_reflector_mode=None)
        Allocate a new SSID and create a STAMP Session (the Sender and the
         Reflector are informed about the new Session).
    start_stamp_session(ssid):
        Start an existing STAMP Session identified by the SSID.
    stop_stamp_session(ssid):
        Stop an existing STAMP Session identified by the SSID.
    destroy_stamp_session(ssid):
        Destroy an existing STAMP Session identified by the SSID.
    get_stamp_results(ssid):
        Get the results fetched by the STAMP Sender for the STAMP Session
         identified by the SSID.
    """

    def __init__(self, debug=False, storage=None, mongodb_client=None):
        """
        Constructs all the necessary attributes for the Controller object.

        Parameters
        ----------
        debug : bool, optional
            Define whether to enable or not the debug mode (default: False).
        """

        # Cache for gRPC stubs
        self.reflector_stubs = dict()
        self.sender_stubs = dict()
        # Cache for gRPC channels
        self.reflector_channels = dict()
        self.sender_channels = dict()
        # Debug mode
        self.debug = debug
        # Setup storage driver
        if storage == 'mongodb':
            from .mongodb_driver import MongoDBDriver
            self.storage = MongoDBDriver(mongodb_client=mongodb_client)
        elif storage is None:
            from .local_storage import LocalStorageDriver
            self.storage = LocalStorageDriver()
        else:
            logger.warning('Unrecognized or Unsupported storage driver %s. '
                           'Using loacl storage,.', storage)
            from .local_storage import LocalStorageDriver
            self.storage = LocalStorageDriver()
        # Set logging
        if self.debug:
            logger.setLevel(level=logging.DEBUG)
        else:
            logger.setLevel(level=logging.INFO)

    def get_grpc_channel_sender_cached(self, node):
        stub = self.sender_stubs.get(node.node_id, None)
        if stub is None:
            channel, stub = get_grpc_channel_sender(ip=node.grpc_ip,
                                                    port=node.grpc_port)
            self.sender_channels[node.node_id] = channel
            self.sender_stubs[node.node_id] = stub
        else:
            channel = self.reflector_channels[node.node_id]
        return channel, stub

    def get_grpc_channel_reflector_cached(self, node):
        stub = self.reflector_stubs.get(node.node_id, None)
        if stub is None:
            channel, stub = get_grpc_channel_reflector(ip=node.grpc_ip,
                                                       port=node.grpc_port)
            self.reflector_channels[node.node_id] = channel
            self.reflector_stubs[node.node_id] = stub
        else:
            channel = self.reflector_channels[node.node_id]
        return channel, stub

    def close_grpc_channel_sender(self, node):
        channel = self.sender_channels.get(node.node_id, None)
        if channel is None:
            logger.warning('gRPC channel to node %s does not exist', node.node_id)
            logger.warning('Nothing to do.')
            return
        channel.close()
        self.sender_channels[node.node_id] = None
        self.sender_stubs[node.node_id] = None

    def close_grpc_channel_reflector(self, node):
        channel = self.reflector_channels.get(node.node_id, None)
        if channel is None:
            logger.warning('gRPC channel to node %s does not exist', node.node_id)
            logger.warning('Nothing to do.')
            return
        channel.close()
        self.reflector_channels[node.node_id] = None
        self.reflector_stubs[node.node_id] = None

    def add_stamp_sender(self, node_id, grpc_ip, grpc_port, ip, udp_port=None,
                         node_name=None, interfaces=None,
                         stamp_source_ipv6_address=None, initialize=True,
                         tenantid='1'):
        """
        Add a STAMP Sender to the Controller inventory.

        Parameters
        ----------
        node_id : str
            An identifier to identify the STAMP Sender
        udp_port : int, optional
            The UDP port of the Sender to be used by STAMP. If it is None, the
             port is randomly chosen by the Sender (default is None).
        node_name : str, optional
            A human-friendly name for the STAMP node. If this parameter is
            None, the node identifier (node_id) is used as node name
            (default: None).
        interfaces : list, optional
            The list of the interfaces on which the STAMP node will listen for
             STAMP packets. If this parameter is None, the node will listen on
             all the interfaces (default is None).
        stamp_source_ipv6_address : str, optional
            The IPv6 address to be used as source IPv6 address of the STAMP
             packets. This can be overridden by providing a IPv6 address to the
             create_stamp_session method. If None, the Sender/Reflector will
             use the loopback IPv6 address as STAMP Source Address
             (default: None).
        initialize : bool, optional
            Whether to automatically initialize the STAMP Sender or not.

        Raises
        ------
        NodeIdAlreadyExistsError
            If `node_id` is already used.
        """

        logger.debug('Adding a new STAMP Sender:\n'
                     'node_id=%s, grpc_ip=%s, grpc_port=%s, ip=%s, '
                     'udp_port=%s, node_name=%s, interfaces=%s, '
                     'stamp_source_ipv6_address=%s', node_id, grpc_ip,
                     grpc_port, ip, udp_port, node_name, interfaces,
                     stamp_source_ipv6_address)

        return self.add_stamp_node(
            node_id=node_id,
            grpc_ip=grpc_ip,
            grpc_port=grpc_port,
            ip=ip,
            interfaces=interfaces,
            stamp_source_ipv6_address=stamp_source_ipv6_address,
            initialize=initialize,
            is_sender=True,
            is_reflector=False,
            sender_port=udp_port,
            node_name=node_name
        )

    def add_stamp_reflector(self, node_id, grpc_ip, grpc_port, ip, udp_port,
                            node_name=None, interfaces=None,
                            stamp_source_ipv6_address=None, initialize=True,
                            tenantid='1'):
        """
        Add a STAMP Reflector to the Controller inventory.

        node_id : str
            An identifier to identify the STAMP Reflector
        udp_port : int
            The UDP port of the Reflector to be used by STAMP.
        node_name : str, optional
            A human-friendly name for the STAMP node. If this parameter is
            None, the node identifier (node_id) is used as node name
            (default: None).
        interfaces : list, optional
            The list of the interfaces on which the STAMP node will listen for
             STAMP packets. If this parameter is None, the node will listen on
             all the interfaces (default is None).
        stamp_source_ipv6_address : str, optional
            The IPv6 address to be used as source IPv6 address of the STAMP
             packets. This can be overridden by providing a IPv6 address to the
             create_stamp_session method. If None, the Sender/Reflector will
             use the loopback IPv6 address as STAMP Source Address
             (default: None).
        initialize : bool, optional
            Whether to automatically initialize the STAMP Sender or not.

        Raises
        ------
        NodeIdAlreadyExistsError
            If `node_id` is already used.
        """

        logger.debug('Adding a new STAMP Reflector:\n'
                     'node_id=%s, grpc_ip=%s, grpc_port=%s, ip=%s, '
                     'udp_port=%s, node_name=%s, interfaces=%s, '
                     'stamp_source_ipv6_address=%s', node_id, grpc_ip,
                     grpc_port, ip, udp_port, node_name, interfaces,
                     stamp_source_ipv6_address)

        return self.add_stamp_node(
            node_id=node_id,
            grpc_ip=grpc_ip,
            grpc_port=grpc_port,
            ip=ip,
            interfaces=interfaces,
            stamp_source_ipv6_address=stamp_source_ipv6_address,
            initialize=initialize,
            is_sender=False,
            is_reflector=True,
            reflector_port=udp_port,
            node_name=node_name
        )

    def add_stamp_node(self, node_id, grpc_ip, grpc_port, ip, node_name=None,
                       interfaces=None, stamp_source_ipv6_address=None,
                       initialize=True, is_sender=False, is_reflector=False,
                       sender_port=None, reflector_port=None, tenantid='1'):
        """
        Add a STAMP Node to the Controller inventory.

        node_id : str
            An identifier to identify the STAMP Node
        node_name : str, optional
            A human-friendly name for the STAMP node. If this parameter is
            None, the node identifier (node_id) is used as node name
            (default: None).
        interfaces : list, optional
            The list of the interfaces on which the STAMP node will listen for
             STAMP packets. If this parameter is None, the node will listen on
             all the interfaces (default is None).
        stamp_source_ipv6_address : str, optional
            The IPv6 address to be used as source IPv6 address of the STAMP
             packets. This can be overridden by providing a IPv6 address to the
             create_stamp_session method. If None, the STAMP node will
             use the loopback IPv6 address as STAMP Source Address
             (default: None).
        initialize : bool, optional
            Whether to automatically initialize the STAMP Node or not.
        is_sender : bool, optional
            True if the STAMP Node is a Sender (default: False).
        is_reflector : bool, optional
            True if the STAMP Node is a Reflector (default: False).
        sender_port : int
            The UDP port of the Node to be used by STAMP. If not it is chosen
            randomly by the STAMP Node (default: None).
        reflector_port : int
            The UDP port of the Node to be used by STAMP. If not it is chosen
            randomly by the STAMP Node (default: None).

        Raises
        ------
        NodeIdAlreadyExistsError
            If `node_id` is already used.
        """

        logger.debug('Adding a new STAMP Node:\n'
                     'node_id=%s, grpc_ip=%s, grpc_port=%s, ip=%s, '
                     'sender_udp_port=%s, reflector_udp_port=%s, '
                     'interfaces=%s, stamp_source_ipv6_address=%s, '
                     'is_sender=%s, is_reflector=%s, node_name=%s',
                     node_id, grpc_ip, grpc_port, ip, sender_port,
                     reflector_port, interfaces, stamp_source_ipv6_address,
                     is_sender, is_reflector, node_name)

        # Check if node is a Sender or a Reflector
        if not is_sender and not is_reflector:
            logger.error('The node should be a Sender or a Reflector')

        # Check if node_id is already taken
        if self.storage.get_stamp_node(node_id=node_id,
                                       tenantid=tenantid) is not None:
            raise NodeIdAlreadyExistsError

        # Create a STAMP Sender object and store it
        node = STAMPNode(
            node_id=node_id, grpc_ip=grpc_ip, grpc_port=grpc_port, ip=ip,
            sender_udp_port=sender_port,
            reflector_udp_port=reflector_port, node_name=node_name,
            interfaces=interfaces,
            stamp_source_ipv6_address=stamp_source_ipv6_address,
            is_sender=is_sender, is_reflector=is_reflector)
        self.storage.create_stamp_node(node=node, tenantid=tenantid)

        # Initialize the node, eventually
        if initialize:
            if is_sender:
                self.init_sender(node_id)
            if is_reflector:
                self.init_reflector(node_id)

    def remove_stamp_node(self, node_id, tenantid='1'):
        """
        Remove a STAMP node.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Reflector to be initialized.

        Returns
        -------
        None

        Raises
        ------
        NodeIdNotFoundError
            If `node_id` does not correspond to any existing node.
        STAMPSessionsExistError
            If STAMP Sessions exist on the node.
        """

        logger.debug('Removing STAMP node')

        # Retrieve the node information from the dict of STAMP nodes
        logger.debug('Checking if node exists')
        node = self.storage.get_stamp_node(node_id=node_id, tenantid=tenantid)
        if node is None:
            logger.error('STAMP node not found')
            raise NodeIdNotFoundError

        if node.sessions_count != 0:
            raise STAMPSessionsExistError

        if node.is_sender_initialized:
            self.reset_stamp_sender(node_id=node_id)

        if node.is_reflector_initialized:
            self.reset_stamp_reflector(node_id=node_id)

        # Remove the STAMP node
        self.storage.remove_stamp_node(node_id=node_id, tenantid=tenantid)

    def init_sender(self, node_id, tenantid='1'):
        """
        Establish a gRPC connection to a STAMP Session Sender and initialize
         it.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Sender to be initialized.

        Returns
        -------
        None

        Raises
        ------
        NodeIdNotFoundError
            If `node_id` does not correspond to any existing node.
        NotAStampSenderError
            If node identified by `node_id` is not a STAMP Sender.
        """

        logger.debug('Initializing STAMP Sender, node_id: %s', node_id)

        # Retrieve the node information from the dict of STAMP nodes
        logger.debug('Checking if the node exists')
        node = self.storage.get_stamp_node(node_id=node_id, tenantid=tenantid)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        logger.debug('Verifying if the node is a STAMP Sender')
        if not node.is_stamp_sender():
            raise NotAStampSenderError

        # Check if the node has been already initialized
        logger.debug('Checking if node is initialized')
        if node.is_sender_initialized:
            raise NodeInitializedError

        # Establish a gRPC connection to the Sender
        logger.debug('Establish a gRPC connection to the STAMP Sender')
        _, stub = self.get_grpc_channel_sender_cached(node=node)

        # Prepare the gRPC request message
        logger.debug('Preparing the gRPC request message')
        request = stamp_sender_pb2.InitStampSenderRequest()
        request.sender_udp_port = node.sender_udp_port
        request.interfaces.extend(node.interfaces)
        if node.stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = node.stamp_source_ipv6_address

        # Invoke the Init RPC
        logger.debug('Sending the Init request on the gRPC Channel')
        reply = stub.Init(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot init Sender: %s', reply.description)
            # Close the gRPC channel
            self.close_grpc_channel_sender(node=node)
            # Raise an exception
            raise InitSTAMPNodeError(reply.description)

        # Mark the node as initialized
        node.is_sender_initialized = True

        logger.debug('Init operation completed successfully')

    def init_reflector(self, node_id, tenantid='1'):
        """
        Establish a gRPC connection to a STAMP Session Reflector and initialize
         it.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Reflector to be initialized.

        Returns
        None

        Raises
        ------
        NodeIdNotFoundError
            If `node_id` does not correspond to any existing node.
        NotAStampReflectorError
            If node identified by `node_id` is not a STAMP Reflector.
        """

        logger.debug('Initializing STAMP Reflector, node_id: %s', node_id)

        # Retrieve the node information from the dict of STAMP nodes
        logger.debug('Checking if the node exists')
        node = self.storage.get_stamp_node(node_id=node_id, tenantid=tenantid)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Reflector
        logger.debug('Verifying if the node is a STAMP Reflector')
        if not node.is_stamp_reflector():
            raise NotAStampReflectorError

        # Check if the node has been already initialized
        logger.debug('Checking if node is initialized')
        if node.is_reflector_initialized:
            raise NodeInitializedError

        # Establish a gRPC connection to the Reflector
        logger.debug('Establish a gRPC connection to the STAMP Reflector')
        channel, stub = self.get_grpc_channel_reflector_cached(node=node)

        # Prepare the gRPC request message
        logger.debug('Preparing the gRPC request message')
        request = stamp_reflector_pb2.InitStampReflectorRequest()
        request.reflector_udp_port = node.reflector_udp_port
        request.interfaces.extend(node.interfaces)
        if node.stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = node.stamp_source_ipv6_address

        # Invoke Init RPC
        logger.debug('Sending the Init request on the gRPC Channel')
        reply = stub.Init(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot init Reflector: %s', reply.description)
            # Close the gRPC channel
            self.close_grpc_channel_reflector(node=node)
            # Raise an exception
            raise InitSTAMPNodeError(reply.description)

        # Mark the node as initialized
        node.is_reflector_initialized = True

        logger.debug('Init operation completed successfully')

    def init_stamp_node(self, node_id, tenantid='1'):
        """
        Establish a gRPC connection to a STAMP Session Node (either Sender or
         Reflector) and initialize it.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Reflector to be initialized.

        Returns
        -------
        None

        Raises
        ------
        NodeIdNotFoundError
            If `node_id` does not correspond to any existing node.
        InvalidStampNodeError
            If node is neither a STAMP Sender nor a STAMP Reflector.
        """

        logger.debug('Initializing STAMP node')

        # Retrieve the node information from the dict of STAMP nodes
        logger.debug('Checking if node exists')
        node = self.storage.get_stamp_node(node_id=node_id, tenantid=tenantid)
        if node is None:
            logger.error('STAMP node not found')
            raise NodeIdNotFoundError

        # Check if the node is a STAMP Sender or a STAMP Reflector
        logger.debug('Detecting node type')
        if node.is_stamp_sender():
            logger.debug('Node is a STAMP Sender')
            self.init_sender(node_id)
        if node.is_stamp_reflector():
            logger.debug('Node is a STAMP Reflector')
            self.init_reflector(node_id)

    def reset_stamp_sender(self, node_id, tenantid='1'):
        """
        Reset a STAMP Sender and tear down the gRPC connection.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Reflector to be reset.

        Returns
        None
        """

        logger.debug('Reset STAMP Sender requested, node_id: %s', node_id)

        # Retrieve the node information from the dict of STAMP nodes
        logger.debug('Retrieving node information')
        node = self.storage.get_stamp_node(node_id=node_id, tenantid=tenantid)
        if node is None:
            logger.error('Node %s not found', node_id)
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        logger.debug('Checking if node is a STAMP Sender')
        if not node.is_stamp_sender():
            logger.error('Node %s is not a STAMP Sender', node_id)
            raise NotAStampSenderError

        # Check if the node has been initialized
        logger.debug('Checking if node has been initialized')
        if not node.is_sender_initialized:
            logger.error('Cannot reset a uninitialized node')
            raise NodeNotInitializedError

        # Prepare the request message
        logger.debug('Preparing gRPC request message')
        request = stamp_sender_pb2.ResetStampSenderRequest()

        # Invoke the Reset RPC
        logger.debug('Invoking the Reset() RPC')
        _, grpc_stub_sender = self.get_grpc_channel_sender_cached(node=node)
        reply = grpc_stub_sender.Reset(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot reset STAMP Node: %s', reply.description)
            # Raise an exception
            raise ResetSTAMPNodeError(reply.description)

        # Tear down the gRPC channel to the node
        self.close_grpc_channel_sender(node=node)

        # Mark the node as not initialized
        self.storage.set_sender_inizialized(
            node_id=node_id, tenantid=tenantid, is_initialized=False)

        logger.debug('Reset() RPC completed successfully')

    def reset_stamp_reflector(self, node_id, tenantid='1'):
        """
        Reset a STAMP Reflector and tear down the gRPC connection.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Reflector to be reset.

        Returns
        None
        """

        logger.debug('Reset STAMP Reflector requested, node_id: %s', node_id)

        # Retrieve the node information from the dict of STAMP nodes
        logger.debug('Retrieving node information')
        node = self.storage.get_stamp_node(node_id=node_id, tenantid=tenantid)
        if node is None:
            logger.error('Node %s not found', node_id)
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Reflector
        logger.debug('Checking if node is a STAMP Reflector')
        if not node.is_stamp_reflector():
            logger.error('Node %s is not a STAMP Reflector', node_id)
            raise NotAStampReflectorError

        # Check if the node has been initialized
        logger.debug('Checking if node has been initialized')
        if not node.is_reflector_initialized:
            logger.error('Cannot reset a uninitialized node')
            raise NodeNotInitializedError

        # Prepare the request message
        logger.debug('Preparing gRPC request message')
        request = stamp_reflector_pb2.ResetStampReflectorRequest()

        # Invoke the Reset RPC
        logger.debug('Invoking the Reset() RPC')
        _, grpc_stub_reflector = \
            self.get_grpc_channel_reflector_cached(node=node)
        reply = grpc_stub_reflector.Reset(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot reset STAMP Node: %s', reply.description)
            # Raise an exception
            raise ResetSTAMPNodeError(reply.description)

        # Tear down the gRPC channel to the node
        self.close_grpc_channel_reflector(node=node)

        # Mark the node as not initialized
        self.storage.set_reflector_inizialized(
            node_id=node_id, tenantid=tenantid, is_initialized=False)

        logger.debug('Reset() RPC completed successfully')

    def reset_stamp_node(self, node_id, tenantid='1'):
        """
        Reset a STAMP node (either Sender or Reflector) and tear down the gRPC
         connection.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP node to be reset.

        Returns
        -------
        None

        Raises
        ------
        NodeIdNotFoundError
            If `node_id` does not correspond to any existing node.
        InvalidStampNodeError
            If node is neither a STAMP Sender nor a STAMP Reflector.
        """

        logger.debug('Resetting STAMP node')

        # Retrieve the node information from the dict of STAMP nodes
        logger.debug('Checking if node exists')
        node = self.storage.get_stamp_node(node_id=node_id, tenantid=tenantid)
        if node is None:
            logger.error('STAMP node not found')
            raise NodeIdNotFoundError

        # Check if the node is a STAMP Sender or a STAMP Reflector
        # and send reset command
        logger.debug('Detecting node type')
        if node.is_stamp_sender():
            logger.debug('Node is a STAMP Sender')
            self.reset_stamp_sender(node_id)
        if node.is_stamp_reflector():
            logger.debug('Node is a STAMP Reflector')
            self.reset_stamp_reflector(node_id)

    def _create_stamp_sender_session(self, ssid, sender, reflector,
                                     sidlist=[], interval=10, auth_mode=None,
                                     key_chain=None, timestamp_format=None,
                                     packet_loss_type=None,
                                     delay_measurement_mode=None,
                                     source_ip=None):
        """
        Internal function used to create a STAMP Session on the STAMP Sender.
         You should not use this function. Instead, you should use
         create_stamp_session.

        Parameters
        ----------

        ssid : int
            The 16-bit STAMP Session Identifier (SSID).
        sender : controller.STAMPNode
            An object that represents the STAMP Session Sender
        reflector : controller.STAMPNode
            An object that represents the STAMP Session Reflector.
        sidlist : list, optional
            The segment list for the direct path (Sender -> Reflector)
             (default []).
        interval : int, optional
            Time (in seconds) between two STAMP Test packets (default 10).
        auth_mode : common_pb2.AuthenticationMode, optional
            The authentication mode (i.e. unauthenticated or authenticated).
             If this parameter is None, the authentication mode is decided by
             the STAMP node (default None).
        key_chain : str, optional
            Key chain, used for authenticated mode (default None).
        timestamp_format : common_pb2.TimestampFormat, optional
            The timestamp format to use for the STAMP Test packets (i.e. NTP
             or PTPv2). If this parameter is None, the timestamp format is
             decided by the STAMP node (default None).
        packet_loss_type : common_pb2.PacketLossType, optional
            The packet loss type (i.e. Round Trip or Far End or Near End).
             If this parameter is None, the packet loss type is decided by the
             STAMP node (default None).
        delay_measurement_mode : common_pb2.DelayMeasurementMode, optional
            The delay measurement mode (i.e. One-Way, Two-Way or Loopback).
             If this parameter is None, the delay measurement mode is decided
             by the STAMP node (default None).
        source_ip : str, optional
            The IPv6 address to be used as source IPv6 address of the STAMP
            packets. If None, the address stored in the STAMP Node instance
            will be used as STAMP Source Address (default: None).

        Returns
        -------
        The STAMP Sender Reply received from the Sender
        """

        # Create a request message
        logger.debug('Preparing gRPC request message')
        request = stamp_sender_pb2.CreateStampSenderSessionRequest()

        # Fill the request message
        request.ssid = ssid
        request.sidlist.segments.extend(sidlist)
        request.interval = interval
        request.stamp_params.reflector_ip = reflector.ip
        request.stamp_params.reflector_udp_port = reflector.reflector_udp_port

        # Fill in optional parameters
        if source_ip is not None:
            request.stamp_source_ipv6_address = source_ip
        if auth_mode is not None:
            request.stamp_params.auth_mode = \
                py_to_grpc(AuthenticationMode, auth_mode)
        if key_chain is not None:
            request.stamp_params.key_chain = key_chain
        if timestamp_format is not None:
            request.stamp_params.timestamp_format = \
                py_to_grpc(TimestampFormat, timestamp_format)
        if packet_loss_type is not None:
            request.stamp_params.packet_loss_type = \
                py_to_grpc(PacketLossType, packet_loss_type)
        if delay_measurement_mode is not None:
            request.stamp_params.delay_measurement_mode = \
                py_to_grpc(DelayMeasurementMode, delay_measurement_mode)

        # Invoke the RPC
        logger.debug('Invoke the CreateStampSession() RPC on STAMP Sender')
        _, grpc_stub_sender = self.get_grpc_channel_sender_cached(node=sender)
        reply = grpc_stub_sender.CreateStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot create STAMP Session: %s', reply.description)
            # Raise an exception
            raise CreateSTAMPSessionError(reply.description)

        # Return the reply
        logger.debug('CreateStampSession() RPC completed successfully')
        return reply

    def _create_stamp_reflector_session(self, ssid, sender, reflector,
                                        return_sidlist, auth_mode=None,
                                        key_chain=None, timestamp_format=None,
                                        session_reflector_mode=None,
                                        source_ip=None):
        """
        Internal function used to create a STAMP Session on the STAMP
         Reflector. You should not use this function. Instead, you should use
         create_stamp_session.

        Parameters
        ----------
        ssid : int
            The 16-bit STAMP Session Identifier (SSID).
        sender : controller.STAMPNode
            An object that represents the STAMP Session Sender
        reflector : controller.STAMPNode
            An object that represents the STAMP Session Reflector.
        return_sidlist : list, optional
            The segment list for the return path (Reflector -> Sender)
             (default []).
        interval : int, optional
            Time (in seconds) between two STAMP Test packets (default 10).
        auth_mode : common_pb2.AuthenticationMode, optional
            The authentication mode (i.e. unauthenticated or authenticated).
             If this parameter is None, the authentication mode is decided by
             the STAMP node (default None).
        key_chain : str, optional
            Key chain, used for authenticated mode (default None).
        timestamp_format : common_pb2.TimestampFormat, optional
            The timestamp format to use for the STAMP Test packets (i.e. NTP
             or PTPv2). If this parameter is None, the timestamp format is
             decided by the STAMP node (default None).
        session_reflector_mode : common_pb2.SessionReflectorMode, optional
            The session reflector mode (i.e. Stateless or Stateful).
             If this parameter is None, the packet loss type is decided by the
             STAMP node (default None).
        source_ip : str, optional
            The IPv6 address to be used as source IPv6 address of the STAMP
            packets. If None, the address stored in the STAMP Node instance
            will be used as STAMP Source Address (default: None).

        Returns
        -------
        The STAMP Reflector Reply received from the Reflector.
        """

        # Create a request message
        logger.debug('Preparing gRPC request message')
        request = stamp_reflector_pb2.CreateStampReflectorSessionRequest()

        # Fill the request message
        request.ssid = ssid
        request.return_sidlist.segments.extend(return_sidlist)
        request.stamp_params.reflector_udp_port = reflector.reflector_udp_port

        # Fill in optional parameters
        if source_ip is not None:
            request.stamp_source_ipv6_address = source_ip
        if auth_mode is not None:
            request.stamp_params.auth_mode = \
                py_to_grpc(AuthenticationMode, auth_mode)
        if key_chain is not None:
            request.stamp_params.key_chain = key_chain
        if timestamp_format is not None:
            request.stamp_params.timestamp_format = \
                py_to_grpc(TimestampFormat, timestamp_format)
        if session_reflector_mode is not None:
            request.stamp_params.session_reflector_mode = \
                py_to_grpc(SessionReflectorMode, session_reflector_mode)

        # Invoke the RPC
        logger.debug('Invoke the CreateStampSession() RPC on STAMP Reflector')
        _, grpc_stub_reflector = self.get_grpc_channel_reflector_cached(node=reflector)
        reply = grpc_stub_reflector.CreateStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot create STAMP Session: %s', reply.description)
            # Raise an exception
            raise CreateSTAMPSessionError(reply.description)

        # Return the reply
        logger.debug('CreateStampSession() RPC completed successfully')
        return reply

    def create_stamp_session(self, sender_id, reflector_id=None, sidlist=[],
                             return_sidlist=[], interval=10, auth_mode=None,
                             key_chain=None, timestamp_format=None,
                             packet_loss_type=None,
                             delay_measurement_mode=None,
                             session_reflector_mode=None,
                             store_individual_delays=False,
                             sender_source_ip=None,
                             reflector_source_ip=None, description=None,
                             duration=0, tenantid='1'):
        """
        Allocate a new SSID and create a STAMP Session (the Sender and the
         Reflector are informed about the new Session).

        Parameters
        ----------
        sender_id : str
            The node ID of the STAMP Session Sender
        reflector : str, optional
            The node ID of the STAMP Session Reflector. If None, we
             assume that the Reflector is not under control of this controller
             (default None).
        sidlist : list, optional
            The segment list for the direct path (Sender -> Reflector)
             (default []).
        return_sidlist : list, optional
            The segment list for the return path (Reflector -> Sender)
             (default []).
        interval : int, optional
            Time (in seconds) between two STAMP Test packets (default 10).
        auth_mode : str, optional
            The authentication mode.
             If this parameter is None, the authentication mode is decided by
             the STAMP node (default None).
             Possible values: [unauthenticated, hmac-sha-256].
        key_chain : str, optional
            Key chain, used for authenticated mode (default None).
        timestamp_format : str, optional
            The timestamp format to use for the STAMP Test packets (i.e. NTP
             or PTPv2). If this parameter is None, the timestamp format is
             decided by the STAMP node (default None).
             Possible values: [ntp, ptp].
        packet_loss_type : str, optional
            The packet loss type (i.e. Round Trip or Far End or Near End).
             If this parameter is None, the packet loss type is decided by the
             STAMP node (default None).
             Possible values: [round-trip, near-end, far-end].
        delay_measurement_mode : str, optional
            The delay measurement mode (i.e. One-Way, Two-Way or Loopback).
             If this parameter is None, the delay measurement mode is decided
             by the STAMP node (default None).
             Possible values: [one-way, two-way, loopback].
        session_reflector_mode : str, optional
            The session reflector mode (i.e. Stateless or Stateful).
             If this parameter is None, the packet loss type is decided by the
             STAMP node (default None).
             Possible values: [stateless, stateful].
        store_individual_delays : bool, optional
            Define whether to store the individual delay values or not
             (default: False).
        sender_source_ip : str, optional
            The IPv6 address to be used as source IPv6 address of the STAMP
            packets sent by the Sender. If None, the address stored in the
            STAMP Sender instance will be used as STAMP Source Address
            (default: None).
        reflector_source_ip : str, optional
            The IPv6 address to be used as source IPv6 address of the STAMP
            packets sent by the Reflector. If None, the address stored in the
            STAMP Reflector instance will be used as STAMP Source Address
            (default: None).
        description : str, optional
            An optional string which describes the STAMP Session to be
            created. If this parameter is None, the SSID is used as Session
            description (default: None).

        Returns
        -------
        ssid : int
            The SSID allocated to the STAMP Session.
        """

        logger.debug('Create STAMP Session operation requested')

        # Check if the STAMP Sender exists
        sender = self.storage.get_stamp_node(
            node_id=sender_id, tenantid=tenantid)
        if sender is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        if not sender.is_stamp_sender():
            raise NotAStampSenderError

        # Check if the STAMP Sender has been initialized
        if not sender.is_sender_initialized:
            raise NodeNotInitializedError

        # Check if the STAMP Reflector exists
        reflector = self.storage.get_stamp_node(
            node_id=reflector_id, tenantid=tenantid)
        if reflector is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Reflector
        if not reflector.is_stamp_reflector():
            raise NotAStampReflectorError

        # Check if the STAMP Reflector has been initialized
        if not reflector.is_reflector_initialized:
            raise NodeNotInitializedError

        # Pick a SSID from the reusable SSIDs pool
        # If the pool is empty, we take a new SSID
        ssid = self.storage.get_new_ssid(tenantid=tenantid)

        # Create STAMP Session on the Sender
        logger.debug('Create STAMP Session on STAMP Sender')
        sender_reply = self._create_stamp_sender_session(
            ssid=ssid, sender=sender, reflector=reflector,
            sidlist=sidlist, interval=interval, auth_mode=auth_mode,
            key_chain=key_chain, timestamp_format=timestamp_format,
            packet_loss_type=packet_loss_type,
            delay_measurement_mode=delay_measurement_mode,
            source_ip=sender_source_ip)

        # Create STAMP Session on the Reflector
        if reflector is not None:
            logger.debug('Create STAMP Session on STAMP Reflector')
            reflector_reply = self._create_stamp_reflector_session(
                ssid=ssid, sender=sender, reflector=reflector,
                return_sidlist=return_sidlist, auth_mode=auth_mode,
                key_chain=key_chain, timestamp_format=timestamp_format,
                session_reflector_mode=session_reflector_mode,
                source_ip=reflector_source_ip)

        # Extract the STAMP parameters from the gRPC request
        # Both the Sender and the Reflector report the STAMP parameters to the
        # controller to inform it about the values chosen for the optional
        # parameters

        sender_key_chain = sender_reply.stamp_params.key_chain
        sender_timestamp_format = grpc_to_py_resolve_defaults(
            TimestampFormat, sender_reply.stamp_params.timestamp_format)
        packet_loss_type = grpc_to_py_resolve_defaults(
            PacketLossType, sender_reply.stamp_params.packet_loss_type)
        delay_measurement_mode = \
            grpc_to_py_resolve_defaults(
                DelayMeasurementMode,
                sender_reply.stamp_params.delay_measurement_mode)

        reflector_key_chain = reflector_reply.stamp_params.key_chain
        reflector_timestamp_format = \
            grpc_to_py_resolve_defaults(
                TimestampFormat, reflector_reply.stamp_params.timestamp_format)
        session_reflector_mode = \
            grpc_to_py_resolve_defaults(
                SessionReflectorMode,
                reflector_reply.stamp_params.session_reflector_mode)

        # Sender and Reflector "reflector_udp_port" must be equal
        if sender_reply.stamp_params.reflector_udp_port != \
                reflector_reply.stamp_params.reflector_udp_port:
            logger.fatal('BUG - reflector_udp_port must be equal both on the '
                         'Sender and the Reflector')
            exit(-1)

        # Sender and Reflector auth mode must be equal
        if sender_reply.stamp_params.auth_mode != \
                reflector_reply.stamp_params.auth_mode:
            logger.fatal('BUG - Sender auth mode and Reflector auth mode '
                         'must be equal')
            exit(-1)

        auth_mode = grpc_to_py_resolve_defaults(
            AuthenticationMode, sender_reply.stamp_params.auth_mode)

        # Use SSID as STAMP Session description if description has been not set
        if description is None:
            description = f'Session {ssid}'

        # Create a STAMP Session object
        stamp_session = STAMPSession(
            ssid=ssid,
            description=description,
            sender=sender,
            reflector=reflector,
            sidlist=sidlist,
            return_sidlist=return_sidlist,
            interval=interval,
            auth_mode=auth_mode,
            sender_key_chain=sender_key_chain,
            reflector_key_chain=reflector_key_chain,
            sender_timestamp_format=sender_timestamp_format,
            reflector_timestamp_format=reflector_timestamp_format,
            packet_loss_type=packet_loss_type,
            delay_measurement_mode=delay_measurement_mode,
            session_reflector_mode=session_reflector_mode,
            store_individual_delays=store_individual_delays,
            duration=duration
        )

        # Store STAMP Session
        self.storage.create_stamp_session(
            session=stamp_session, tenantid=tenantid)

        # Return the SSID allocated for the STAMP session
        logger.debug('STAMP Session created successfully, ssid: %d', ssid)
        return ssid

    def start_stamp_session(self, ssid, tenantid='1'):
        """
        Start an existing STAMP Session identified by the SSID.

        Parameters
        ----------
        ssid : int
            16-bit STAMP Session Identifier (SSID).

        Returns
        -------
        None
        """

        logger.debug('Starting STAMP Session, ssid: %d', ssid)

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.storage.get_stamp_session(
            ssid=ssid, tenantid=tenantid)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Check if STAMP Session is running
        if stamp_session.is_running:
            logger.error('Session %d already running', ssid)
            raise STAMPSessionRunningError(ssid=ssid)

        # Start STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
            logger.debug('Starting STAMP Session on Reflector')
            request = stamp_reflector_pb2.StartStampReflectorSessionRequest()
            request.ssid = ssid
            _, grpc_stub_reflector = self.get_grpc_channel_reflector_cached(node=stamp_session.reflector)
            reply = grpc_stub_reflector.StartStampSession(
                request)
            if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                logger.error(
                    'Cannot start STAMP Session on Reflector: %s',
                    reply.description)
                # Raise an exception
                raise StartSTAMPSessionError(reply.description)

        # Start STAMP Session on the Sender
        logger.debug('Starting STAMP Session on Sender')
        request = stamp_sender_pb2.StartStampSenderSessionRequest()
        request.ssid = ssid
        _, grpc_stub_sender = self.get_grpc_channel_sender_cached(node=stamp_session.sender)
        reply = grpc_stub_sender.StartStampSession(
            request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot start STAMP Session on Sender: %s', reply.description)
            # Raise an exception
            raise StartSTAMPSessionError(reply.description)

        # Schedule a stop session operation if <duration> parameter has been
        # set; if duration is 0, we don't schedule a stop task and session
        # will run indefinitely or until we don't call stop_stamp_session()
        if stamp_session.duration is not None and stamp_session.duration != 0:
            logger.debug('Scheduling a stop session operation in '
                         f'{stamp_session.duration} seconds')
            Thread(target=self._stop_stamp_session_after,
                   kwargs={'ssid': ssid,
                           'seconds': stamp_session.duration}).start()

        logger.debug('STAMP Session started successfully')
        self.storage.set_session_running(
            ssid=ssid, tenantid=tenantid, is_running=True)

    def stop_stamp_session(self, ssid, tenantid='1'):
        """
        Stop an existing STAMP Session identified by the SSID.

        Parameters
        ----------
        ssid : int
            16-bit STAMP Session Identifier (SSID).

        Returns
        -------
        None
        """

        logger.debug('Stopping STAMP Session, ssid: %d', ssid)

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.storage.get_stamp_session(
            ssid=ssid, tenantid=tenantid)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Check if STAMP Session is running
        if not stamp_session.is_running:
            logger.error('Session %d not running', ssid)
            raise STAMPSessionNotRunningError(ssid=ssid)

        # Stop STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
            logger.debug('Stopping STAMP Session on Reflector')
            request = stamp_reflector_pb2.StopStampReflectorSessionRequest()
            request.ssid = ssid
            _, grpc_stub_reflector = self.get_grpc_channel_reflector_cached(node=stamp_session.reflector)
            reply = grpc_stub_reflector.StopStampSession(
                request)
            if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                logger.error(
                    'Cannot stop STAMP Session on Reflector: %s',
                    reply.description)
                # Raise an exception
                raise StopSTAMPSessionError(reply.description)

        # Stop STAMP Session on the Sender
        logger.debug('Stopping STAMP Session on Sender')
        request = stamp_sender_pb2.StopStampSenderSessionRequest()
        request.ssid = ssid
        _, grpc_stub_sender = self.get_grpc_channel_sender_cached(node=stamp_session.sender)
        reply = grpc_stub_sender.StopStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot stop STAMP Session on Sender: %s', reply.description)
            # Raise an exception
            raise StopSTAMPSessionError(reply.description)

        logger.debug('STAMP Session stopped successfully')
        self.storage.set_session_running(
            ssid=ssid, tenantid=tenantid, is_running=False)

    def _stop_stamp_session_after(self, ssid, seconds):
        """
        Wait for X seconds and stop an existing STAMP Session identified by
        the SSID.

        Parameters
        ----------
        ssid : int
            16-bit STAMP Session Identifier (SSID).
        seconds : int
            The seconds to wait before stopping the session.

        Returns
        -------
        None
        """

        logger.debug('Stopping STAMP Session after %d, ssid: %d',
                     seconds, ssid)

        # Wait for X seconds
        time.sleep(seconds)

        # Stop the STAMP Session
        try:
            return self.stop_stamp_session(ssid)
        except STAMPSessionNotRunningError:
            logger.warning('Scheduled STAMP Session stop operation failed:'
                           'Session %d already stopped', ssid)

    def destroy_stamp_session(self, ssid, tenantid='1'):
        """
        Destroy an existing STAMP Session identified by the SSID.

        Parameters
        ----------
        ssid : int
            16-bit STAMP Session Identifier (SSID).

        Returns
        -------
        None
        """

        logger.debug('Destroying STAMP Session, ssid: %d', ssid)

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.storage.get_stamp_session(
            ssid=ssid, tenantid=tenantid)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Destroy STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
            logger.debug('Destroying STAMP Session on Reflector')
            request = stamp_reflector_pb2.DestroyStampReflectorSessionRequest()
            request.ssid = ssid
            _, grpc_stub_reflector = self.get_grpc_channel_reflector_cached(node=stamp_session.reflector)
            reply = (grpc_stub_reflector.DestroyStampSession(request))
            if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                logger.error(
                    'Cannot destroy STAMP Session on Reflector: %s',
                    reply.description)
                # Raise an exception
                raise DestroySTAMPSessionError(reply.description)

        # Destroy STAMP Session on the Sender
        logger.debug('Destroying STAMP Session on Sender')
        request = stamp_sender_pb2.DestroyStampSenderSessionRequest()
        request.ssid = ssid
        _, grpc_stub_sender = self.get_grpc_channel_sender_cached(node=stamp_session.sender)
        reply = (grpc_stub_sender.DestroyStampSession(request))
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot destroy STAMP Session on Sender: %s',
                reply.description)
            # Raise an exception
            raise DestroySTAMPSessionError(reply.description)

        # Remove the STAMP Session from the STAMP Sessions dict
        self.storage.remove_stamp_session(ssid=ssid, tenantid=tenantid)

        # Mark the SSID as reusable
        self.storage.release_ssid(ssid=ssid, tenantid=tenantid)

        # Decrease sessions counter on the Sender and Reflector
        self.storage.decrease_sessions_count(stamp_session.sender.node_id, tenantid)
        self.storage.decrease_sessions_count(stamp_session.reflector.node_id, tenantid)

        logger.debug('STAMP Session destroyed successfully')

    def fetch_stamp_results(self, ssid, tenantid='1'):
        """
        Get the results fetched by the STAMP Sender for the STAMP Session
         identified by the SSID and store them internally to the controller.

        Parameters
        ----------
        ssid : int
            The 16-bit STAMP Session Identifier (SSID).

        Returns
        -------
        None
        """

        logger.debug('Fetching results for STAMP Session, ssid: %d', ssid)

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.storage.get_stamp_session(
            ssid=ssid, tenantid=tenantid)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Get results of the STAMP Session
        logger.debug('Fetching results from STAMP Sender')
        request = stamp_sender_pb2.GetStampSessionResultsRequest()
        request.ssid = ssid
        _, grpc_stub_sender = self.get_grpc_channel_sender_cached(node=stamp_session.sender)
        reply = (grpc_stub_sender.GetStampSessionResults(request))
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot fetch STAMP Session results (SSID %d): %s',
                request.ssid, reply.description)
            # Raise an exception
            raise GetSTAMPResultsError(reply.description)

        logger.debug('Got %f results', len(reply.results))

        # Iterate on each received result
        for res in reply.results:
            # Extract the timestamps
            test_pkt_tx_timestamp = res.test_pkt_tx_timestamp
            reply_pkt_tx_timestamp = res.reply_pkt_tx_timestamp
            reply_pkt_rx_timestamp = res.reply_pkt_rx_timestamp
            test_pkt_rx_timestamp = res.test_pkt_rx_timestamp

            # Compute the delay of the direct path (Sender to Reflector)
            delay_direct_path = compute_packet_delay(
                tx_timestamp=test_pkt_tx_timestamp,
                rx_timestamp=test_pkt_rx_timestamp
            )

            # Compute the delay of the return path (Reflector to Sender)
            delay_return_path = compute_packet_delay(
                tx_timestamp=reply_pkt_tx_timestamp,
                rx_timestamp=reply_pkt_rx_timestamp
            )

            # Store the instant delays and update the mean delay of the direct
            # path using the Welford Online Algorithm
            stamp_session.stamp_session_direct_path_results.add_new_delay(
                new_delay=delay_direct_path)

            # Store the instant delays and update the mean delay of the return
            # path using the Welford Online Algorithm
            stamp_session.stamp_session_return_path_results.add_new_delay(
                new_delay=delay_return_path)

            logger.debug('\n*********')
            logger.debug('Delay measured for the direct path: %f',
                         delay_direct_path)
            logger.debug('Delay measured for the return path: %f',
                         delay_return_path)
            logger.debug('Mean delay for the direct path: %f', stamp_session
                         .stamp_session_direct_path_results.mean_delay)
            logger.debug('Mean delay for the return path: %f', stamp_session
                         .stamp_session_return_path_results.mean_delay)
            logger.debug('*********\n')

    def get_measurement_sessions(self, ssid=None, tenantid='1'):
        """
        Return the STAMP Sessions.

        Parameters
        ----------
        ssid : int, optional
            The 16-bit STAMP Session Identifier (SSID). If None, return the
            all the STAMP Sessions.

        Returns
        -------
        stamp_sessions : list
            The list of STAMP Sessions.
        """

        # If SSID is provided return the corresponding STAMP Session
        if ssid is not None:
            if self.storage.stamp_session_exists(ssid=ssid, tenantid=tenantid):
                # Fetch results from the STAMP Sender
                self.fetch_stamp_results(ssid=ssid)
                # Return the STAMP Session
                return self.storage.get_stamp_sessions(session_ids=[ssid],
                                                       tenantid=tenantid)
            else:
                # SSID not found, return an empty list
                return []

        # No SSID provided

        # Fetch all the results
        for _ssid in self.storage.get_stamp_sessions(tenantid=tenantid,
                                                     return_dict=True):
            self.fetch_stamp_results(ssid=_ssid)

        # Return all the STAMP Sessions
        return self.storage.get_stamp_sessions(tenantid=tenantid)

    def get_stamp_results_average(self, ssid, fetch_results_from_stamp=False):
        """
        Return the results (average delays only) stored in the controller.

        Parameters
        ----------
        ssid : int
            The 16-bit STAMP Session Identifier (SSID).
        fetch_results_from_stamp : bool, optional
            Whether to fetch the new results from the STAMP Sender. If
            False, only the results already stored in the controller inventory
            are returned (default: False).

        Returns
        -------
        direct_path_mean_delay : float
            The mean delay of the direct path (Sender -> Reflector).
        return_path_mean_delay : float
            The mean delay of the return path (Reflector -> Sender).

        Raises
        ------
        STAMPSessionNotFoundError
            If the STAMP Session does not exist.
        """

        logger.debug('Get results average for STAMP Session, ssid: %d', ssid)

        # Get the results
        direct_path_results, return_path_results = \
            self.get_stamp_results(self, ssid, fetch_results_from_stamp)

        # Return the mean delay
        return (direct_path_results.mean_delay, return_path_results.mean_delay)

    def get_stamp_results(self, ssid, fetch_results_from_stamp=False,
                          tenantid='1'):
        """
        Return the results stored in the controller.

        Parameters
        ----------
        ssid : int
            The 16-bit STAMP Session Identifier (SSID).
        fetch_results_from_stamp : bool, optional
            Whether to fetch the new results from the STAMP Sender. If
            False, only the results already stored in the controller inventory
            are returned (default: False).

        Returns
        -------
        direct_path_results : controller.STAMPSessionResults
            The delay results of the direct path (Sender -> Reflector).
        return_path_results : controller.STAMPSessionResults
            The delay results of the return path (Reflector -> Sender).

        Raises
        ------
        STAMPSessionNotFoundError
            If the STAMP Session does not exist.
        """

        logger.debug('Get results for STAMP Session, ssid: %d', ssid)

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.storage.get_stamp_session(
            ssid=ssid, tenantid=tenantid)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Eventually, fetch new results from the STAMP Sender
        if fetch_results_from_stamp:
            self.fetch_stamp_results(ssid)

        # Return the mean delay
        return (stamp_session.stamp_session_direct_path_results,
                stamp_session.stamp_session_return_path_results)

    def print_stamp_results(self, ssid, fetch_results_from_stamp=False):
        """
        Print the results stored in the controller.

        Parameters
        ----------
        ssid : int
            The 16-bit STAMP Session Identifier (SSID).
        fetch_results_from_stamp : bool, optional
            Whether to fetch the new results from the STAMP Sender. If
            False, only the results already stored in the controller inventory
            are returned (default: False).

        Returns
        -------
        None.
        """

        logger.debug('Print results for STAMP Session, ssid: %d', ssid)

        # Get results from the controller inventory
        mean_delay_direct_path, mean_delay_return_path = \
            self.get_stamp_results_average(ssid, fetch_results_from_stamp)

        # Print results
        print()
        print()
        print('*** Results for STAMP Session {ssid} ***'.format(ssid=ssid))
        print('Mean delay for the direct path: {delay}'
              .format(delay=mean_delay_direct_path))
        print('Mean delay for the return path: {delay}'
              .format(delay=mean_delay_return_path))
        print('*******************************************')
        print()


class STAMPControllerServicer(controller_pb2_grpc.STAMPControllerService):
    """
    Provides methods that allow a controller to control the STAMP Sessions
    through the gRPC protocol.
    """

    def __init__(self, controller):
        # Initialize super class STAMPControllerService
        super().__init__()
        # Reference to the Controller to be controlled through the
        # gRPC interface
        self.controller = controller

    def RegisterStampSender(self, request, context):
        """RPC used to register a new STAMP Sender."""

        logger.debug('RegisterStampSender RPC invoked. Request: %s', request)

        # Extract the node id from the request message
        node_id = request.node_id

        # Extract gRPC IP address from the request message
        grpc_ip = request.grpc_ip

        # Extract gRPC port from the request message
        grpc_port = request.grpc_port

        # Extract IP address from the request message
        ip = request.ip

        # Extract STAMP UDP port from the request message
        # This parameter is optional, therefore we set it to None if it is
        # not provided
        udp_port = None
        if request.udp_port:
            udp_port = request.udp_port

        # Extract the intrfaces from the request message
        # This parameter is optional, therefore we set it to None if it is
        # not provided
        interfaces = None
        if request.interfaces:
            interfaces = list(request.interfaces)

        # Extract STAMP Source IPv6 address from the request message
        # This parameter is optional, therefore we set it to None if it is
        # not provided
        stamp_source_ipv6_address = None
        if request.stamp_source_ipv6_address:
            stamp_source_ipv6_address = request.stamp_source_ipv6_address

        # Extract "initialize" parameter. If "initialize" is set, we need to
        # initialize the node after its registration.
        initialize = request.initialize

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to register the STAMP Session Sender
        try:
            self.controller.add_stamp_sender(
                node_id, grpc_ip, grpc_port, ip, udp_port, interfaces,
                stamp_source_ipv6_address, initialize, tenantid
            )
        except NodeIdAlreadyExistsError:
            # The node is already registered, return an error
            logging.error('Cannot complete the requested operation: '
                          'Sender node has been already registered')
            return controller_pb2.RegisterStampSenderReply(
                status=common_pb2.StatusCode.STATUS_CODE_ALREADY_REGISTERED,
                description='Sender node has been already registered')

        # Return with success status code
        logger.debug('RegisterStampSender RPC completed')
        return controller_pb2.RegisterStampSenderReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def RegisterStampReflector(self, request, context):
        """RPC used to register a new STAMP Reflector."""

        logger.debug(
            'RegisterStampReflector RPC invoked. Request: %s', request)

        # Extract the node id from the request message
        node_id = request.node_id

        # Extract gRPC IP address from the request message
        grpc_ip = request.grpc_ip

        # Extract gRPC port from the request message
        grpc_port = request.grpc_port

        # Extract IP address from the request message
        ip = request.ip

        # Extract STAMP UDP port from the request message
        udp_port = request.udp_port

        # Extract the intrfaces from the request message
        # This parameter is optional, therefore we set it to None if it is
        # not provided
        interfaces = None
        if request.interfaces:
            interfaces = list(request.interfaces)

        # Extract STAMP Source IPv6 address from the request message
        # This parameter is optional, therefore we set it to None if it is
        # not provided
        stamp_source_ipv6_address = None
        if request.stamp_source_ipv6_address:
            stamp_source_ipv6_address = request.stamp_source_ipv6_address

        # Extract "initialize" parameter. If "initialize" is set, we need to
        # initialize the node after its registration.
        initialize = request.initialize

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to register the STAMP Session Reflector
        try:
            self.controller.add_stamp_reflector(
                node_id, grpc_ip, grpc_port, ip, udp_port, interfaces,
                stamp_source_ipv6_address, initialize, tenantid
            )
        except NodeIdAlreadyExistsError:
            # The node is already registered, return an error
            logging.error('Cannot complete the requested operation: '
                          'Reflector node has been already registered')
            return controller_pb2.RegisterStampReflectorReply(
                status=common_pb2.StatusCode.STATUS_CODE_ALREADY_REGISTERED,
                description='Reflector node has been already registered')

        # Return with success status code
        logger.debug('RegisterStampReflector RPC completed')
        return controller_pb2.RegisterStampReflectorReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def UnregisterStampNode(self, request, context):
        """RPC used to unregister a STAMP node."""

        logger.debug('UnregisterStampNode RPC invoked. Request: %s', request)

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to unregister the STAMP node
        try:
            self.controller.unregister_stamp_node(node_id=request.node_id,
                                                  tenantid=tenantid)
        except NodeIdNotFoundError:
            # No STAMP node corresponding to the node ID, return an error
            logging.error('Cannot complete the requested operation: '
                          'No STAMP node corresponding to the node ID')
            return controller_pb2.InitStampNodeReply(
                status=common_pb2.StatusCode.STATUS_CODE_NODE_NOT_FOUND,
                description='No STAMP node corresponding to the node ID')
        except STAMPSessionsExistError:
            # The provided UDP port is not valid, return an error
            logging.error('Cannot complete the requested operation: '
                          'STAMP Sessions exist on the node. Destroy all '
                          'sessions before calling unregister.')
            return controller_pb2.InitStampNodeReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_EXISTS,
                description='STAMP Sessions exist on the node. Destroy all '
                            'sessions before calling unregister.')

        # Return with success status code
        logger.debug('InitStampNode RPC completed')
        return controller_pb2.InitStampNodeReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def InitStampNode(self, request, context):
        """RPC used to initialize the STAMP nodes."""

        logger.debug('InitStampNode RPC invoked. Request: %s', request)

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to initialize the STAMP node
        try:
            self.controller.init_stamp_node(node_id=request.node_id,
                                            tenantid=tenantid)
        except NodeIdNotFoundError:
            # No STAMP node corresponding to the node ID, return an error
            logging.error('Cannot complete the requested operation: '
                          'No STAMP node corresponding to the node ID')
            return controller_pb2.InitStampNodeReply(
                status=common_pb2.StatusCode.STATUS_CODE_NODE_NOT_FOUND,
                description='No STAMP node corresponding to the node ID')
        except InvalidStampNodeError:
            # The provided UDP port is not valid, return an error
            logging.error('Cannot complete the requested operation: '
                          'Invalid STAMP node')
            return controller_pb2.InitStampNodeReply(
                status=common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT,
                description='Invalid STAMP node')

        # Return with success status code
        logger.debug('InitStampNode RPC completed')
        return controller_pb2.InitStampNodeReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def ResetStampNode(self, request, context):
        """RPC used to reset the STAMP nodes."""

        logger.debug('ResetStampNode RPC invoked. Request: %s', request)
        logger.info('Attempting to reset STAMP node')

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Reset the STAMP node
        try:
            self.controller.reset_stamp_node(node_id=request.node_id,
                                             tenantid=tenantid)
        except NodeIdNotFoundError:
            # No STAMP node corresponding to the node ID, return an error
            logging.error('Cannot complete the requested operation: '
                          'No STAMP node corresponding to the node ID')
            return controller_pb2.InitStampNodeReply(
                status=common_pb2.StatusCode.STATUS_CODE_NODE_NOT_FOUND,
                description='No STAMP node corresponding to the node ID')
        except InvalidStampNodeError:
            # The provided UDP port is not valid, return an error
            logging.error('Cannot complete the requested operation: '
                          'Invalid STAMP node')
            return controller_pb2.InitStampNodeReply(
                status=common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT,
                description='Invalid STAMP node')

        # Return with success status code
        logger.debug('ResetStampNode RPC completed')
        return controller_pb2.ResetStampNodeReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def CreateStampSession(self, request, context):
        """RPC used to create a new STAMP Session."""

        logger.debug('CreateStampSession RPC invoked. Request: %s', request)

        # Extract parameters from the gRPC request
        description = None
        if request.description:
            description = request.description

        sender_id = request.sender_id

        reflector_id = None
        if request.reflector_id:
            reflector_id = request.reflector_id

        direct_sidlist = None
        if request.direct_sidlist:
            direct_sidlist = list(request.direct_sidlist.segments)

        return_sidlist = None
        if request.return_sidlist:
            return_sidlist = list(request.return_sidlist.segments)

        interval = 10  # default interval is 10 seconds
        if request.interval:
            interval = request.interval

        duration = 0
        if request.duration:
            duration = request.duration

        auth_mode = None
        if request.stamp_params.auth_mode:
            auth_mode = request.stamp_params.auth_mode

        key_chain = None
        if request.stamp_params.key_chain:
            key_chain = request.stamp_params.key_chain

        timestamp_format = None
        if request.stamp_params.timestamp_format:
            timestamp_format = request.stamp_params.timestamp_format

        packet_loss_type = None
        if request.stamp_params.packet_loss_type:
            packet_loss_type = request.stamp_params.packet_loss_type

        delay_measurement_mode = None
        if request.stamp_params.delay_measurement_mode:
            delay_measurement_mode = \
                request.stamp_params.delay_measurement_mode

        session_reflector_mode = None
        if request.stamp_params.session_reflector_mode:
            session_reflector_mode = \
                request.stamp_params.session_reflector_mode

        sender_source_ip = None
        if request.sender_source_ipv6_address:
            sender_source_ip = request.sender_source_ipv6_address

        reflector_source_ip = None
        if request.reflector_source_ipv6_address:
            reflector_source_ip = request.reflector_source_ipv6_address

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to create a STAMP Session
        try:
            ssid = self.controller.create_stamp_session(
                sender_id=sender_id, reflector_id=reflector_id,
                sidlist=direct_sidlist, return_sidlist=return_sidlist,
                interval=interval, auth_mode=auth_mode, key_chain=key_chain,
                timestamp_format=timestamp_format,
                packet_loss_type=packet_loss_type,
                delay_measurement_mode=delay_measurement_mode,
                session_reflector_mode=session_reflector_mode,
                store_individual_delays=True,
                sender_source_ip=sender_source_ip,
                reflector_source_ip=reflector_source_ip,
                description=description, duration=duration,
                tenantid=tenantid
            )
        except CreateSTAMPSessionError as err:
            # Failed to create a STAMP Session, return an error
            logging.error('Cannot complete the requested operation: '
                          'Cannot create STAMP Session: %s', err.msg)
            # Return an error
            return controller_pb2.CreateStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='Cannot create STAMP Session: {err}'
                            .format(err=err.msg))
        except NodeIdNotFoundError:
            # No STAMP node corresponding to the node ID, return an error
            logging.error('Cannot complete the requested operation: '
                          'No STAMP node corresponding to the node ID')
            return controller_pb2.CreateStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_NODE_NOT_FOUND,
                description='No STAMP node corresponding to the node ID')
        except NotAStampSenderError:
            # The node specified as STAMP sender is not a sender,
            # return an error
            logging.error('Cannot complete the requested operation: '
                          'Node is not a STAMP Sender: %s', sender_id)
            return controller_pb2.CreateStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT,
                description='Node is not a STAMP Sender: {sender_id}'
                            .format(sender_id=sender_id))
        except NodeNotInitializedError:
            # The STAMP node is not initialized, return an error
            logging.error('Cannot complete the requested operation: '
                          'STAMP Node is not initialized')
            return controller_pb2.CreateStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
                description='STAMP node is not initialized')
        except NotAStampReflectorError:
            # The node specified as STAMP reflector is not a reflector,
            # return an error
            logging.error('Cannot complete the requested operation: '
                          'Node is not a STAMP Reflector: %s', reflector_id)
            return controller_pb2.CreateStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT,
                description='Node is not a STAMP Reflector: {reflector_id}')

        # Return with success status code
        logger.debug('CreateStampSession RPC completed')
        return controller_pb2.CreateStampSessionReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS, ssid=ssid)

    def StartStampSession(self, request, context):
        """RPC used to start a STAMP Session."""

        logger.debug('StartStampSession RPC invoked. Request: %s', request)

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to start the STAMP Session
        try:
            self.controller.start_stamp_session(ssid=request.ssid,
                                                tenantid=tenantid)
        except StartSTAMPSessionError as err:
            # Failed to start the STAMP Session, return an error
            logging.error('Cannot complete the requested operation: '
                          'Cannot start the STAMP Session: %s', err.msg)
            # Return an error
            return controller_pb2.StartStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='Cannot start the STAMP Session: {err}'
                            .format(err=err.msg))
        except STAMPSessionNotFoundError:
            # STAMP Session not found, return an error
            logging.error('Cannot complete the requested operation: '
                          'STAMP Session not found, ssid %s', request.ssid)
            # Return an error
            return controller_pb2.StartStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='STAMP Session not found, ssid {ssid}'
                            .format(ssid=request.ssid))

        # Return with success status code
        logger.debug('StartStampSessionReply RPC completed')
        return controller_pb2.StartStampSessionReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def StopStampSession(self, request, context):
        """RPC used to stop a running STAMP Session."""

        logger.debug('StopStampSession RPC invoked. Request: %s', request)

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to stop the STAMP Session
        try:
            self.controller.stop_stamp_session(ssid=request.ssid,
                                               tenantid=tenantid)
        except StopSTAMPSessionError as err:
            # Failed to stop the STAMP Session, return an error
            logging.error('Cannot complete the requested operation: '
                          'Cannot stop the STAMP Session: %s', err.msg)
            # Return an error
            return controller_pb2.StopStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='Cannot stop the STAMP Session: {err}'
                            .format(err=err.msg))
        except STAMPSessionNotFoundError:
            # STAMP Session not found, return an error
            logging.error('Cannot complete the requested operation: '
                          'STAMP Session not found, ssid %s', request.ssid)
            # Return an error
            return controller_pb2.StopStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='STAMP Session not found, ssid {ssid}'
                            .format(ssid=request.ssid))

        # Return with success status code
        logger.debug('StopStampSessionReply RPC completed')
        return controller_pb2.StopStampSessionReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def DestroyStampSession(self, request, context):
        """RPC used to destroy an existing STAMP Session."""

        logger.debug('DestroyStampSession RPC invoked. Request: %s', request)

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to destroy the STAMP Session
        try:
            self.controller.destroy_stamp_session(ssid=request.ssid,
                                                  tenantid=tenantid)
        except DestroySTAMPSessionError as err:
            # Failed to destroy the STAMP Session, return an error
            logging.error('Cannot complete the requested operation: '
                          'Cannot destroy the STAMP Session: %s', err.msg)
            # Return an error
            return controller_pb2.StopStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='Cannot destroy the STAMP Session: {err}'
                            .format(err=err.msg))
        except STAMPSessionNotFoundError:
            # STAMP Session not found, return an error
            logging.error('Cannot complete the requested operation: '
                          'STAMP Session not found, ssid %s', request.ssid)
            # Return an error
            return controller_pb2.StopStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='STAMP Session not found, ssid {ssid}'
                            .format(ssid=request.ssid))

        # Return with success status code
        logger.debug('DestroyStampSession RPC completed')
        return controller_pb2.DestroyStampSessionReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def GetStampResults(self, request, context):
        """RPC used to collect the results of STAMP Session."""

        logger.debug('GetStampResults RPC invoked. Request: %s', request)

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to collect the results of the STAMP Session
        try:
            direct_path_results, return_path_results = \
                self.controller.get_stamp_results(
                    ssid=request.ssid,
                    fetch_results_from_stamp=True,
                    tenantid=tenantid)
        except STAMPSessionNotFoundError:
            # The STAMP Session does not exist
            logging.error('SSID %d not found', request.ssid)
            return stamp_sender_pb2.StampResults(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
                description='SSID {ssid} not found'.format(ssid=request.ssid))

        # Retrieve STAMP Session
        try:
            stamp_session = \
                self.controller.get_measurement_sessions(
                    ssid=request.ssid, tenantid=tenantid)[0]
        except STAMPSessionNotFoundError:
            # The STAMP Session does not exist
            logging.error('SSID %d not found', request.ssid)
            return stamp_sender_pb2.StampResults(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
                description='SSID {ssid} not found'.format(ssid=request.ssid))

        # Prepare the gRPC reply
        reply = controller_pb2.GetStampResultsReply()

        # Populate the gRPC reply with the test results
        res = reply.results.add()
        res.ssid = request.ssid
        res.direct_sidlist.segments.extend(stamp_session.sidlist)
        res.return_sidlist.segments.extend(stamp_session.return_sidlist)
        res.measurement_type = \
            controller_pb2.MeasurementType.MEASUREMENT_TYPE_DELAY
        res.measurement_direction = \
            controller_pb2.MeasurementDirection.MEASUREMENT_DIRECTION_BOTH
        res.direct_path_average_delay = direct_path_results.mean_delay
        res.return_path_average_delay = return_path_results.mean_delay
        for delay in direct_path_results.delays:
            direct_path_res = res.direct_path_results.add()
            direct_path_res.id = delay.id
            direct_path_res.value = delay.value
            direct_path_res.timestamp = delay.timestamp
        for delay in return_path_results.delays:
            return_path_res = res.return_path_results.add()
            return_path_res.id = delay.id
            return_path_res.value = delay.value
            return_path_res.timestamp = delay.timestamp

        # Set status code and return
        logger.debug('GetStampResults RPC completed')
        reply.status = common_pb2.StatusCode.STATUS_CODE_SUCCESS
        return reply

    def GetStampSessions(self, request, context):
        """RPC used to collect the STAMP measurement sessions."""

        logger.debug('GetStampSessions RPC invoked. Request: %s', request)

        # Extract SSID from the gRPC request; SSID is optional
        # If not set, we return all the STAMP Sessions
        ssid = None
        if request.ssid:
            ssid = request.ssid

        # Extract Tenant ID
        tenantid = request.tenantid
        if tenantid == '':
            tenantid = '1'

        # Try to collect the results of the STAMP Session
        stamp_sessions = self.controller.get_measurement_sessions(
            ssid=ssid, tenantid=tenantid)

        # Prepare the gRPC reply
        reply = controller_pb2.GetStampSessionsReply()

        # Populate the gRPC reply with the test results
        for stamp_session in stamp_sessions:
            sess = reply.stamp_sessions.add()
            sess.ssid = stamp_session.ssid
            sess.description = stamp_session.description
            if stamp_session.is_running:
                sess.status = controller_pb2.STAMP_SESSION_STATUS_RUNNING
            else:
                sess.status = controller_pb2.STAMP_SESSION_STATUS_STOPPED
            sess.sender_id = stamp_session.sender.node_id
            sess.sender_name = stamp_session.sender.node_name
            if stamp_session.sender.stamp_source_ipv6_address is not None:
                sess.sender_source_ip = \
                    stamp_session.sender.stamp_source_ipv6_address
            sess.reflector_id = stamp_session.reflector.node_id
            sess.reflector_name = stamp_session.reflector.node_name
            if stamp_session.reflector.stamp_source_ipv6_address is not None:
                sess.reflector_source_ip = \
                    stamp_session.reflector.stamp_source_ipv6_address
            sess.interval = stamp_session.interval
            sess.duration = stamp_session.duration
            sess.stamp_params.auth_mode = stamp_session.auth_mode
            sess.stamp_params.key_chain = stamp_session.sender_key_chain
            sess.stamp_params.timestamp_format = \
                stamp_session.sender_timestamp_format
            sess.stamp_params.packet_loss_type = stamp_session.packet_loss_type
            sess.stamp_params.delay_measurement_mode = \
                stamp_session.delay_measurement_mode
            sess.stamp_params.session_reflector_mode = \
                stamp_session.session_reflector_mode
            sess.direct_sidlist.segments.extend(stamp_session.sidlist)
            sess.return_sidlist.segments.extend(stamp_session.return_sidlist)
            sess.average_delay_direct_path = \
                stamp_session.stamp_session_direct_path_results.mean_delay
            sess.average_delay_return_path = \
                stamp_session.stamp_session_return_path_results.mean_delay

        # Set status code and return
        logger.debug('GetStampSessions RPC completed')
        reply.status = common_pb2.StatusCode.STATUS_CODE_SUCCESS
        return reply


def run_grpc_server(grpc_ip: str = None, grpc_port: int = DEFAULT_GRPC_PORT,
                    secure_mode=False, server=None, storage=None,
                    mongodb_client=None):
    """
    Run a gRPC server that will accept RPCs on the provided IP address and
     port and block until the server is terminated.

    Parameters
    ----------
    grpc_ip : str, optional
        IP address on which the gRPC server will accept connections. None
         means "any" (default is None)
    grpc_port : int, optional
        Port on which the gRPC server will accept connections
         (default is 12345).
    secure_mode : bool, optional
        Whether to enable or not gRPC secure mode (default is False).
    server : optional
        An existing gRPC server. If None, a new gRPC server is created.

    Returns
    -------
    The STAMP controller if an existing server has been provided, otherwise
    block indefinitely and never return.
    """

    # Create a Controller object
    controller = Controller(storage=storage, mongodb_client=mongodb_client)

    # If a reference to an existing gRPC server has been passed as argument,
    # attach the gRPC interface to the existing server
    if server is not None:
        controller_pb2_grpc.add_STAMPControllerServiceServicer_to_server(
            STAMPControllerServicer(controller), server)
        return controller

    # Create the gRPC server
    logger.debug('Creating the gRPC server')
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    controller_pb2_grpc.add_STAMPControllerServiceServicer_to_server(
        STAMPControllerServicer(controller), server)

    # Add secure or insecure port, depending on the "secure_mode" chosen
    if secure_mode:
        logging.fatal('Secure mode not yet implemented')
        exit(1)
    else:
        # If gRPC IP address is not provided, listen on any IP address
        if grpc_ip is None:
            # Listen on any IPv4 address
            server.add_insecure_port('0.0.0.0:{port}'.format(port=grpc_port))
            # Listen on any IPv6 address
            server.add_insecure_port('[::]:{port}'.format(port=grpc_port))
        else:
            server.add_insecure_port('{address}:{port}'.format(
                address=grpc_ip, port=grpc_port))

    # Start the server and block until it is terminated
    logger.info('Listening gRPC, port %d', grpc_port)
    server.start()
    server.wait_for_termination()


def parse_arguments():
    """
    This function parses the command-line arguments.

    Returns
    -------
    None.
    """

    parser = argparse.ArgumentParser(
        description='SDN Controller implementation.')
    parser.add_argument('--grpc-ip', dest='grpc_ip', type=str,
                        help='ip address on which the gRPC server will accept '
                             'RPCs. None means "any" (default: None)')
    parser.add_argument('--grpc-port', dest='grpc_port', type=int,
                        default=DEFAULT_GRPC_PORT,
                        help='port on which the gRPC server will accept RPCs '
                             '(default: 12345)')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        default=False, help='Debug mode (default: False')
    args = parser.parse_args()

    return args


if __name__ == '__main__':

    # Parse and extract command-line arguments
    logger.debug('Parsing arguments')
    args = parse_arguments()
    grpc_ip = args.grpc_ip
    grpc_port = args.grpc_port
    debug = args.debug

    # Configure logging
    if debug:
        logger.setLevel(level=logging.DEBUG)
        logger.info('Logging level: DEBUG')
    else:
        logger.setLevel(level=logging.INFO)
        logger.info('Logging level: INFO')

    # Run the gRPC server and block forever
    logger.debug('Starting gRPC server')
    run_grpc_server(grpc_ip, grpc_port)
