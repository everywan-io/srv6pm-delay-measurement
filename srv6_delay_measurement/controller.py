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

from concurrent import futures
import argparse
import logging
import time

import grpc

import common_pb2
import controller_pb2
import controller_pb2_grpc

from exceptions import (
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
    StartSTAMPSessionError,
    StopSTAMPSessionError)

import stamp_reflector_pb2
import stamp_reflector_pb2_grpc
import stamp_sender_pb2
import stamp_sender_pb2_grpc

from utils import grpc_to_py_resolve_defaults, py_to_grpc

from libs.libstamp import (
    AuthenticationMode,
    DelayMeasurementMode,
    PacketLossType,
    SessionReflectorMode,
    TimestampFormat
)


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


class STAMPNode:
    """
    A class to represent a STAMP Node.

    ...

    Attributes
    ----------
    node_id : str
        The identifier of the STAMP node.
    grpc_ip : str
        The gRPC IP address of the STAMP node.
    grpc_port : int
        The gRPC port address of the STAMP node.
    ip : str
        The IP address of the STAMP node.
    node_name : str
        A human-friendly name for the STAMP node.
    interfaces : list, optional
        The list of the interfaces on which the STAMP node will listen for
         STAMP packets. If this parameter is None, the node will listen on all
         the interfaces (default is None).
    grpc_channel : grpc._channel.Channel
        gRPC channel to the node.
    grpc_stub : :object:
        gRPC stub to interact with the node.
    stamp_source_ipv6_address : str
        The IPv6 address to be used as source IPv6 address of the STAMP
            packets. This can be overridden by providing a IPv6 address to the
            create_stamp_session method. If None, the Sender/Reflector will
            use the loopback IPv6 address as STAMP Source Address.
    is_initialized : bool
        Flag indicating whether the node has been initialized or not.

    Methods
    -------
    """

    def __init__(self, node_id, grpc_ip, grpc_port, ip, node_name=None,
                 interfaces=None, stamp_source_ipv6_address=None):
        """
        A class to represent a STAMP node.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP node.
        grpc_ip : str
            The gRPC IP address of the STAMP node.
        grpc_port : int
            The gRPC port address of the STAMP node.
        ip : str
            The IP address of the STAMP node.
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
        """

        # Store parameters
        self.node_id = node_id
        self.grpc_ip = grpc_ip
        self.grpc_port = grpc_port
        self.ip = ip
        self.node_name = node_name if node_name is not None else node_id
        self.interfaces = interfaces
        self.stamp_source_ipv6_address = stamp_source_ipv6_address
        # gRPC Channel and Stub are initially empty
        # They will be set when the STAMP node is initialized and a gRPC
        # connection to the node is established
        self.grpc_channel = None
        self.grpc_stub = None
        # Flag indicating whether the node has been initialized or not
        self.is_initialized = False
        # Number of STAMP Sessions on the node
        self.sessions_count = 0

    def is_stamp_sender(self):
        return isinstance(self, STAMPSender)

    def is_stamp_reflector(self):
        return isinstance(self, STAMPReflector)


class STAMPSender(STAMPNode):
    """
    A class to represent a STAMP Sender.

    ...

    Attributes
    ----------
    node_id : str
        The identifier of the STAMP node.
    grpc_ip : str
        The gRPC IP address of the STAMP node.
    grpc_port : int
        The gRPC port address of the STAMP node.
    ip : str
        The IP address of the STAMP node.
    udp_port : int
        UDP port used by STAMP. If it is None, the Sender port will be chosen
         randomly.
    node_name : str
        A human-friendly name for the STAMP node.
    interfaces : list
        The list of the interfaces on which the STAMP node will listen for
         STAMP packets. If this parameter is None, the node will listen on all
         the interfaces.
    stamp_source_ipv6_address : str
        The IPv6 address to be used as source IPv6 address of the STAMP
            packets. This can be overridden by providing a IPv6 address to the
            create_stamp_session method. If None, the Sender/Reflector will
            use the loopback IPv6 address as STAMP Source Address.

    Methods
    -------
    """

    def __init__(self, node_id, grpc_ip, grpc_port, ip, udp_port=None,
                 node_name=None, interfaces=None,
                 stamp_source_ipv6_address=None):
        """
        A class to represent a STAMP Sender.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP node.
        grpc_ip : str
            The gRPC IP address of the STAMP node.
        grpc_port : int
            The gRPC port address of the STAMP node.
        ip : str
            The IP address of the STAMP node.
        udp_port : int, optional
            UDP port used by STAMP. If it is None, the Sender port will be
             chosen randomly (default None).
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
        """

        # Set parameters for a generic STAMP node
        super().__init__(node_id=node_id, grpc_ip=grpc_ip,
                         grpc_port=grpc_port, ip=ip, node_name=node_name,
                         interfaces=interfaces,
                         stamp_source_ipv6_address=stamp_source_ipv6_address)
        # Set the UDP port of the Sender
        self.udp_port = udp_port


class STAMPReflector(STAMPNode):
    """
    A class to represent a STAMP Reflector.

    ...

    Attributes
    ----------
    node_id : str
        The identifier of the STAMP node.
    grpc_ip : str
        The gRPC IP address of the STAMP node.
    grpc_port : int
        The gRPC port address of the STAMP node.
    ip : str
        The IP address of the STAMP node.
    udp_port : int
        UDP port used by STAMP.
    node_name : str
        A human-friendly name for the STAMP node.
    interfaces : list
        The list of the interfaces on which the STAMP node will listen for
         STAMP packets. If this parameter is None, the node will listen on all
         the interfaces.
    stamp_source_ipv6_address : str
        The IPv6 address to be used as source IPv6 address of the STAMP
            packets. This can be overridden by providing a IPv6 address to the
            create_stamp_session method. If None, the Sender/Reflector will
            use the loopback IPv6 address as STAMP Source Address.

    Methods
    -------
    """

    def __init__(self, node_id, grpc_ip, grpc_port, ip, udp_port,
                 node_name=None, interfaces=None,
                 stamp_source_ipv6_address=None):
        """
        Constructs all the necessary attributes for the STAMP Reflector object.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP node.
        grpc_ip : str
            The gRPC IP address of the STAMP node.
        grpc_port : int
            The gRPC port address of the STAMP node.
        ip : str
            The IP address of the STAMP node.
        udp_port : int
            UDP port used by STAMP.
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
        """

        # Set parameters for a generic STAMP node
        super().__init__(node_id=node_id, grpc_ip=grpc_ip,
                         grpc_port=grpc_port, ip=ip, node_name=node_name,
                         interfaces=interfaces,
                         stamp_source_ipv6_address=stamp_source_ipv6_address)
        # Set the UDP port of the Reflector
        self.udp_port = udp_port


class STAMPSession:
    """
    A class to represent a STAMP Session.

    ...

    Attributes
    ----------
    ssid : int
        16-bit Segment Session Identifier (SSID) of the STAMP Session.
    description : str
        A string which describes the STAMP Session.
    sender : controller.STAMPSender
        An object representing the STAMP Session Sender.
    reflector : controller.STAMPReflector
        An object representing the STAMP Session Reflector.
    sidlist : list
        Segment List for the direct path (Sender to Reflector).
    return_sidlist : list
        Segment List for the return path (Reflector to Sender).
    interval : int
        Time (in seconds) between two STAMP packets.
    auth_mode : common_pb2.AuthenticationMode
        Authentication Mode (i.e. Authenticated or Unauthenticated).
    sender_key_chain : str
        Key chain of the Sender used for the Authenticated Mode.
    reflector_key_chain : str
        Key chain of the Reflector used for the Authenticated Mode.
    sender_timestamp_format : common_pb2.TimestampFormat
        Format of the timestamp used by the Sender (i.e. NTP or PTPv2).
    reflector_timestamp_format : common_pb2.TimestampFormat
        Format of the timestamp used by the Reflector (i.e. NTP or PTPv2).
    packet_loss_type : common_pb2.PacketLossType
        Packet Loss Type (i.e. Round Trip, Near End, Far End).
    delay_measurement_mode : common_pb2.DelayMeasurementMode
        Delay Measurement Mode (i.e. One-Way, Two-Way or Loopback).
    session_reflector_mode : common_pb2.SessionReflectorMode
        Mode used by the STAMP Reflector (i.e. Stateless or Stateful).
    is_running : bool
        Define whether the STAMP Session is running or not.
    stamp_session_direct_path_results : controller.STAMPSessionResults
        An object used to store the results of this STAMP Session for the
         direct path.
    stamp_session_return_path_results : controller.STAMPSessionResults
        An object used to store the results of this STAMP Session for the
         return path.
    store_individual_delays : bool
        Define whether to store the individual delays or not.

    Methods
    -------
    """

    def __init__(self, ssid, description, sender, reflector, sidlist,
                 return_sidlist, interval, auth_mode, sender_key_chain,
                 reflector_key_chain, sender_timestamp_format,
                 reflector_timestamp_format, packet_loss_type,
                 delay_measurement_mode, session_reflector_mode,
                 store_individual_delays=False):
        """
        Constructs all the necessary attributes for the STAMP Reflector object.

        Parameters
        ----------
        ssid : int
            16-bit Segment Session Identifier (SSID) of the STAMP Session.
        description : str
            A string which describes the STAMP Session.
        sender : controller.STAMPSender
            An object representing the STAMP Session Sender.
        reflector : controller.STAMPReflector
            An object representing the STAMP Session Reflector.
        sidlist : list
            Segment List for the direct path (Sender to Reflector).
        return_sidlist : list
            Segment List for the return path (Reflector to Sender).
        interval : int
            Time (in seconds) between two STAMP packets.
        auth_mode : common_pb2.AuthenticationMode
            Authentication Mode (i.e. Authenticated or Unauthenticated).
        sender_key_chain : str
            Key chain of the Sender used for the Authenticated Mode.
        reflector_key_chain : str
            Key chain of the Reflector used for the Authenticated Mode.
        sender_timestamp_format : common_pb2.TimestampFormat
            Format of the timestamp used by the Sender (i.e. NTP or PTPv2).
        reflector_timestamp_format : common_pb2.TimestampFormat
            Format of the timestamp used by the Reflector (i.e. NTP or PTPv2).
        packet_loss_type : common_pb2.PacketLossType
            Packet Loss Type (i.e. Round Trip, Near End, Far End).
        delay_measurement_mode : common_pb2.DelayMeasurementMode
            Delay Measurement Mode (i.e. One-Way, Two-Way or Loopback).
        session_reflector_mode : common_pb2.SessionReflectorMode
            Mode used by the STAMP Reflector (i.e. Stateless or Stateful).
        store_individual_delays : bool, optional
            Define whether to store the individual delays or not (default
            False).
        """

        # Set STAMP session parameters
        self.ssid = ssid
        self.description = description
        self.sender = sender
        self.reflector = reflector
        self.sidlist = sidlist
        self.return_sidlist = return_sidlist
        self.interval = interval
        self.auth_mode = auth_mode
        self.sender_key_chain = sender_key_chain
        self.reflector_key_chain = reflector_key_chain
        self.sender_timestamp_format = sender_timestamp_format
        self.reflector_timestamp_format = reflector_timestamp_format
        self.packet_loss_type = packet_loss_type
        self.delay_measurement_mode = delay_measurement_mode
        self.session_reflector_mode = session_reflector_mode
        # Bool indicating whether the STAMP Session is running or not
        self.is_running = False
        # An object used to store the results of this STAMP Session for the
        # direct path
        self.stamp_session_direct_path_results = STAMPSessionResults(
            ssid=ssid, store_individual_delays=store_individual_delays)
        # An object used to store the results of this STAMP Session for the
        # return path
        self.stamp_session_return_path_results = STAMPSessionResults(
            ssid=ssid, store_individual_delays=store_individual_delays)


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
    channel = grpc.insecure_channel('[{ip}]:{port}'.format(ip=ip, port=port))
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
    channel = grpc.insecure_channel('[{ip}]:{port}'.format(ip=ip, port=port))
    # Get the stub
    stub = stamp_reflector_pb2_grpc.STAMPSessionReflectorServiceStub(channel)

    # Return
    return channel, stub


def compute_packet_delay(tx_timestamp, rx_timestamp):
    """
    Compute the delay of a STAMP packet (either Test or Reply packet).

    Parameters
    ----------
    tx_timestamp : float
        The timestamp associated to the transmission of the STAMP packet.
    rx_timestamp : float
        The timestamp associated to the reception of the STAMP packet.

    Returns
    -------
    delay : float
        The delay of the STAMP packet.
    """

    # Return the delay
    return rx_timestamp - tx_timestamp


def compute_mean_delay_welford(current_mean_delay, count, new_delay):
    """
    Take the mean delay and a new delay value and return the updated mean
     delay which includes the new delay value. This function internally
     use the Welford Online Algorithm for calculating the mean.

    Parameters
    ----------
    current_mean_delay : float
        The existing mean delay.
    count : int
        The number of delay values in the mean computation (including the new
        delay)
    new_delay : float
        The new delay value to be included in the computation of the mean.

    Returns
    -------
    updated_mean_delay : float
        The updated mean delay.
    """

    # Welford Online Algorithm for calculating mean
    return current_mean_delay + (float(new_delay) - current_mean_delay) / count


class STAMPDelayResult:
    """
    A class to represent a STAMP Delay result.

    ...

    Attributes
    ----------
    id : int
        An integer that uniquely identifies a result.
    value : float
        The value of the delay.
    timestamp : float
        The timestamp of the result.
    """

    def __init__(self, id, value, timestamp):
        """
        Constructs all the necessary attributes for the STAMP Delay Result.

        Parameters
        ----------
        id : int
            An integer that uniquely identifies a result.
        value : float
            The value of the delay.
        timestamp : float
            The timestamp of the result.
        """

        # Initialize all the attributes
        self.id = id
        self.value = value
        self.timestamp = timestamp


class STAMPSessionResults:
    """
    A class to represent STAMP Session results.

    ...

    Attributes
    ----------
    ssid : int
        16-bit Segment Session Identifier (SSID) of the STAMP Session.
    store_individual_delays : bool
        Define whether to store the individual delays or not (default False).
    delays : list
        A list of computed delays.
    mean_delay : float
        The mean delay.
    count_packets : int
        The number of STAMP results.
    last_result_id : int
        Last STAMP Delay result identifier.

    Methods
    -------
    add_new_delay(new_delay, store=False, update_mean=True)
        Add a new delay.
    _update_mean_delay(new_delay)
        This is an internal function. Update the mean delay to include a new
         delay value. The mean computation is based on the Welford Online
         Algorithm.
    """

    def __init__(self, ssid, store_individual_delays=False):
        """
        Constructs all the necessary attributes for the STAMP Session Results.

        Parameters
        ----------
        ssid : int
            16-bit Segment Session Identifier (SSID) of the STAMP Session.
        store_individual_delays : bool, optional
            Define whether to store the individual delays or not (default
            False).
        """

        # Initialize all the attributes
        self.ssid = ssid
        self.store_individual_delays = store_individual_delays
        self.delays = list()
        self.mean_delay = 0.0
        self.count_packets = 0
        self.last_result_id = -1

    def add_new_delay(self, new_delay):
        """
        Add a new delay for the measured path and update the mean delay.

        Parameters
        ----------
        new_delay : float
            The delay to add.

        Returns
        -------
        None
        """

        # Increase result identifier
        self.last_result_id += 1
        # Increase packets count
        self.count_packets += 1
        # Store the new delay, eventually
        if self.store_individual_delays:
            self.delays.append(STAMPDelayResult(
                id=self.last_result_id,
                value=new_delay,
                timestamp=time.time()
            ))
        # Update the mean delay
        self._update_mean_delay(new_delay)

    def _update_mean_delay(self, new_delay):
        """
        Update the mean delay to include a new delay value. The mean
         computation is based on the Welford Online Algorithm.

        Parameters
        ----------
        new_delay : float
            The new delay to include in the mean computation.

        Returns
        -------
        None
        """

        # Update mean delay using Welford Online Algorithm
        self.mean_delay = compute_mean_delay_welford(
            current_mean_delay=self.mean_delay,
            count=self.count_packets, new_delay=new_delay)


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
                     interfaces=None, stamp_source_ipv6_address=None,
                     initialize=True)
        Add a STAMP Sender to the Controller inventory.
    add_stamp_reflector(node_id, grpc_ip, grpc_port, ip, udp_port,
                        interfaces=None, stamp_source_ipv6_address=None,
                        initialize=True)
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

    def __init__(self, debug=False):
        """
        Constructs all the necessary attributes for the Controller object.

        Parameters
        ----------
        debug : bool, optional
            Define whether to enable or not the debug mode (default: False).
        """

        # Debug mode
        self.debug = debug
        # Last used STAMP Session Identifier (SSID)
        self.last_ssid = -1
        # Pool of SSID allocated to STAMP Sessions terminated
        # These can be reused for other STAMP Sessions
        self.reusable_ssid = set()
        # Dict mapping node node_id to STAMPNode instance
        self.stamp_nodes = dict()
        # STAMP Sessions
        self.stamp_sessions = dict()
        # Set logging
        if self.debug:
            logger.setLevel(level=logging.DEBUG)
        else:
            logger.setLevel(level=logging.INFO)

    def add_stamp_sender(self, node_id, grpc_ip, grpc_port, ip, udp_port=None,
                         interfaces=None, stamp_source_ipv6_address=None,
                         initialize=True):
        """
        Add a STAMP Sender to the Controller inventory.

        Parameters
        ----------
        node_id : str
            An identifier to identify the STAMP Sender
        udp_port : int, optional
            The UDP port of the Sender to be used by STAMP. If it is None, the
             port is randomly chosen by the Sender (default is None).
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
                     'udp_port=%s, interfaces=%s, '
                     'stamp_source_ipv6_address=%s', node_id, grpc_ip,
                     grpc_port, ip, udp_port, interfaces,
                     stamp_source_ipv6_address)

        # Check if node_id is already taken
        if self.stamp_nodes.get(node_id, None) is not None:
            raise NodeIdAlreadyExistsError

        # Create a STAMP Sender object and store it
        node = STAMPSender(
            node_id=node_id, grpc_ip=grpc_ip, grpc_port=grpc_port, ip=ip,
            udp_port=udp_port, interfaces=interfaces,
            stamp_source_ipv6_address=stamp_source_ipv6_address)
        self.stamp_nodes[node_id] = node

        # Initialize the node, eventually
        if initialize:
            self.init_sender(node_id)

    def add_stamp_reflector(self, node_id, grpc_ip, grpc_port, ip, udp_port,
                            interfaces=None, stamp_source_ipv6_address=None,
                            initialize=True):
        """
        Add a STAMP Reflector to the Controller inventory.

        node_id : str
            An identifier to identify the STAMP Reflector
        udp_port : int
            The UDP port of the Reflector to be used by STAMP.
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
                     'udp_port=%s, interfaces=%s, '
                     'stamp_source_ipv6_address=%s', node_id, grpc_ip,
                     grpc_port, ip, udp_port, interfaces,
                     stamp_source_ipv6_address)

        # Check if node_id is already taken
        if self.stamp_nodes.get(node_id, None) is not None:
            raise NodeIdAlreadyExistsError

        # Create a STAMP Sender object and store it
        node = STAMPReflector(
            node_id=node_id, grpc_ip=grpc_ip, grpc_port=grpc_port, ip=ip,
            udp_port=udp_port, interfaces=interfaces,
            stamp_source_ipv6_address=stamp_source_ipv6_address)
        self.stamp_nodes[node_id] = node

        # Initialize the node, eventually
        if initialize:
            self.init_reflector(node_id)

    def remove_stamp_node(self, node_id):
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
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            logger.error('STAMP node not found')
            raise NodeIdNotFoundError

        if node.sessions_count != 0:
            raise STAMPSessionsExistError

        # Remove the STAMP node
        del self.stamp_nodes[node_id]

    def init_sender(self, node_id):
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
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        logger.debug('Verifying if the node is a STAMP Sender')
        if not node.is_stamp_sender():
            raise NotAStampSenderError

        # Check if the node has been already initialized
        logger.debug('Checking if node is initialized')
        if node.is_initialized:
            raise NodeInitializedError

        # Establish a gRPC connection to the Sender
        logger.debug('Establish a gRPC connection to the STAMP Sender')
        channel, stub = get_grpc_channel_sender(ip=node.grpc_ip,
                                                port=node.grpc_port)

        # Prepare the gRPC request message
        logger.debug('Preparing the gRPC request message')
        request = stamp_sender_pb2.InitStampSenderRequest()
        request.sender_udp_port = node.udp_port
        request.interfaces.extend(node.interfaces)
        if node.stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = node.stamp_source_ipv6_address

        # Invoke the Init RPC
        logger.debug('Sending the Init request on the gRPC Channel')
        reply = stub.Init(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot init Sender: %s', reply.description)
            # Close the gRPC channel
            if channel is not None:
                channel.close()
            # Raise an exception
            raise InitSTAMPNodeError(reply.description)

        # Store the channel and the stub
        node.grpc_channel = channel
        node.grpc_stub = stub

        # Mark the node as initialized
        node.is_initialized = True

        logger.debug('Init operation completed successfully')

    def init_reflector(self, node_id):
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
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Reflector
        logger.debug('Verifying if the node is a STAMP Reflector')
        if not node.is_stamp_reflector():
            raise NotAStampReflectorError

        # Check if the node has been already initialized
        logger.debug('Checking if node is initialized')
        if node.is_initialized:
            raise NodeInitializedError

        # Establish a gRPC connection to the Reflector
        logger.debug('Establish a gRPC connection to the STAMP Reflector')
        channel, stub = get_grpc_channel_reflector(ip=node.grpc_ip,
                                                   port=node.grpc_port)

        # Prepare the gRPC request message
        logger.debug('Preparing the gRPC request message')
        request = stamp_reflector_pb2.InitStampReflectorRequest()
        request.reflector_udp_port = node.udp_port
        request.interfaces.extend(node.interfaces)
        if node.stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = node.stamp_source_ipv6_address

        # Invoke Init RPC
        logger.debug('Sending the Init request on the gRPC Channel')
        reply = stub.Init(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot init Reflector: %s', reply.description)
            # Close the gRPC channel
            if channel is not None:
                channel.close()
            # Raise an exception
            raise InitSTAMPNodeError(reply.description)

        # Store the channel and the stub
        node.grpc_channel = channel
        node.grpc_stub = stub

        # Mark the node as initialized
        node.is_initialized = True

        logger.debug('Init operation completed successfully')

    def init_stamp_node(self, node_id):
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
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            logger.error('STAMP node not found')
            raise NodeIdNotFoundError

        # Check if the node is a STAMP Sender or a STAMP Reflector
        logger.debug('Detecting node type')
        if node.is_stamp_sender():
            logger.debug('Node is a STAMP Sender')
            return self.init_sender(node_id)
        if node.is_stamp_reflector():
            logger.debug('Node is a STAMP Reflector')
            return self.init_reflector(node_id)

        # Node is neither a sender nor a reflector
        logger.error('Node is invalid')
        raise InvalidStampNodeError

    def reset_stamp_sender(self, node_id):
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
        node = self.stamp_nodes.get(node_id, None)
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
        if not node.is_initialized:
            logger.error('Cannot reset a uninitialized node')
            raise NodeNotInitializedError

        # Prepare the request message
        logger.debug('Preparing gRPC request message')
        request = stamp_sender_pb2.ResetStampSenderRequest()

        # Invoke the Reset RPC
        logger.debug('Invoking the Reset() RPC')
        reply = node.grpc_stub.Reset(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot reset STAMP Node: %s', reply.description)
            # Raise an exception
            raise ResetSTAMPNodeError(reply.description)

        # Tear down the gRPC channel to the node
        node.grpc_channel.close()
        node.grpc_channel = None
        node.grpc_stub = None

        # Mark the node as not initialized
        node.is_initialized = False

        logger.debug('Reset() RPC completed successfully')

    def reset_stamp_reflector(self, node_id):
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
        node = self.stamp_nodes.get(node_id, None)
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
        if not node.is_initialized:
            logger.error('Cannot reset a uninitialized node')
            raise NodeNotInitializedError

        # Prepare the request message
        logger.debug('Preparing gRPC request message')
        request = stamp_reflector_pb2.ResetStampReflectorRequest()

        # Invoke the Reset RPC
        logger.debug('Invoking the Reset() RPC')
        reply = node.grpc_stub.Reset(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot reset STAMP Node: %s', reply.description)
            # Raise an exception
            raise ResetSTAMPNodeError(reply.description)

        # Tear down the gRPC channel to the node
        node.grpc_channel.close()
        node.grpc_channel = None
        node.grpc_stub = None

        # Mark the node as not initialized
        node.is_initialized = False

        logger.debug('Reset() RPC completed successfully')

    def reset_stamp_node(self, node_id):
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
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            logger.error('STAMP node not found')
            raise NodeIdNotFoundError

        # Check if the node is a STAMP Sender or a STAMP Reflector
        # and send reset command
        logger.debug('Detecting node type')
        if node.is_stamp_sender():
            logger.debug('Node is a STAMP Sender')
            return self.reset_stamp_sender(node_id)
        if node.is_stamp_reflector():
            logger.debug('Node is a STAMP Reflector')
            return self.reset_stamp_reflector(node_id)

        # Node is neither a sender nor a reflector
        raise InvalidStampNodeError

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
        sender : controller.STAMPSender
            An object that represents the STAMP Session Sender
        reflector : controller.STAMPReflector
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
        request.stamp_params.reflector_udp_port = reflector.udp_port

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
        reply = sender.grpc_stub.CreateStampSession(request)
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
        sender : controller.STAMPSender
            An object that represents the STAMP Session Sender
        reflector : controller.STAMPReflector
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
        request.stamp_params.reflector_udp_port = reflector.udp_port

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
        reply = reflector.grpc_stub.CreateStampSession(request)
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
                             reflector_source_ip=None, description=None):
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
        sender = self.stamp_nodes.get(sender_id, None)
        if sender is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        if not sender.is_stamp_sender():
            raise NotAStampSenderError

        # Check if the STAMP Sender has been initialized
        if not sender.is_initialized:
            raise NodeNotInitializedError

        # Check if the STAMP Reflector exists
        reflector = self.stamp_nodes.get(reflector_id, None)
        if reflector is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Reflector
        if not reflector.is_stamp_reflector():
            raise NotAStampReflectorError

        # Check if the STAMP Reflector has been initialized
        if not reflector.is_initialized:
            raise NodeNotInitializedError

        # Pick a SSID from the reusable SSIDs pool
        # If the pool is empty, we take a new SSID
        if len(self.reusable_ssid) > 0:
            ssid = self.reusable_ssid.pop()
        else:
            ssid = self.last_ssid + 1
            self.last_ssid += 1

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
        sender_timestamp_format = grpc_to_py_resolve_defaults(TimestampFormat, sender_reply.stamp_params.timestamp_format)
        packet_loss_type = grpc_to_py_resolve_defaults(PacketLossType, sender_reply.stamp_params.packet_loss_type)
        delay_measurement_mode = \
            grpc_to_py_resolve_defaults(DelayMeasurementMode, sender_reply.stamp_params.delay_measurement_mode)

        reflector_key_chain = reflector_reply.stamp_params.key_chain
        reflector_timestamp_format = \
            grpc_to_py_resolve_defaults(TimestampFormat, reflector_reply.stamp_params.timestamp_format)
        session_reflector_mode = \
            grpc_to_py_resolve_defaults(SessionReflectorMode, reflector_reply.stamp_params.session_reflector_mode)

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

        auth_mode = grpc_to_py_resolve_defaults(AuthenticationMode, sender_reply.stamp_params.auth_mode)

        # Use SSID as STAMP Session description if description has been not set
        description = description if description is not None else str(ssid)

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
            store_individual_delays=store_individual_delays
        )

        # Store STAMP Session
        self.stamp_sessions[ssid] = stamp_session

        # Increase sessions counter on the Sender and Reflector
        stamp_session.sender.sessions_count += 1
        stamp_session.reflector.sessions_count += 1

        # Return the SSID allocated for the STAMP session
        logger.debug('STAMP Session created successfully, ssid: %d', ssid)
        return ssid

    def start_stamp_session(self, ssid):
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
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Start STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
            logger.debug('Starting STAMP Session on Reflector')
            request = stamp_reflector_pb2.StartStampReflectorSessionRequest()
            request.ssid = ssid
            reply = stamp_session.reflector.grpc_stub.StartStampSession(
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
        reply = stamp_session.sender.grpc_stub.StartStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot start STAMP Session on Sender: %s', reply.description)
            # Raise an exception
            raise StartSTAMPSessionError(reply.description)

        logger.debug('STAMP Session started successfully')
        stamp_session.is_running = True

    def stop_stamp_session(self, ssid):
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
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Stop STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
            logger.debug('Stopping STAMP Session on Reflector')
            request = stamp_reflector_pb2.StopStampReflectorSessionRequest()
            request.ssid = ssid
            reply = stamp_session.reflector.grpc_stub.StopStampSession(request)
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
        reply = stamp_session.sender.grpc_stub.StopStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot stop STAMP Session on Sender: %s', reply.description)
            # Raise an exception
            raise StopSTAMPSessionError(reply.description)

        logger.debug('STAMP Session stopped successfully')
        stamp_session.is_running = False

    def destroy_stamp_session(self, ssid):
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
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Destroy STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
            logger.debug('Destroying STAMP Session on Reflector')
            request = stamp_reflector_pb2.DestroyStampReflectorSessionRequest()
            request.ssid = ssid
            reply = stamp_session.reflector.grpc_stub.DestroyStampSession(
                request)
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
        reply = stamp_session.sender.grpc_stub.DestroyStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot destroy STAMP Session on Sender: %s',
                reply.description)
            # Raise an exception
            raise DestroySTAMPSessionError(reply.description)

        # Remove the STAMP Session from the STAMP Sessions dict
        del self.stamp_sessions[ssid]

        # Mark the SSID as reusable
        self.reusable_ssid.add(ssid)
        
        # Decrease sessions counter on the Sender and Reflector
        stamp_session.sender.sessions_count -= 1
        stamp_session.reflector.sessions_count -= 1

        logger.debug('STAMP Session destroyed successfully')

    def fetch_stamp_results(self, ssid):
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
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            raise STAMPSessionNotFoundError(ssid)

        # Get results of the STAMP Session
        logger.debug('Fetching results from STAMP Sender')
        request = stamp_sender_pb2.GetStampSessionResultsRequest()
        request.ssid = ssid
        reply = stamp_session.sender.grpc_stub.GetStampSessionResults(request)
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

    def get_measurement_sessions(self, ssid=None):
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
        print('ssid\n\n\n\n', ssid)
        if ssid is not None:
            if ssid in self.stamp_sessions:
                return [self.stamp_sessions[ssid]]
            else:
                # SSID not found, return an empty list
                return []

        # No SSID provided, return all the STAMP Sessions
        return self.stamp_sessions.values()

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

    def get_stamp_results(self, ssid, fetch_results_from_stamp=False):
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
        stamp_session = self.stamp_sessions.get(ssid, None)
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

        # Try to register the STAMP Session Sender
        try:
            self.controller.add_stamp_sender(
                node_id, grpc_ip, grpc_port, ip, udp_port, interfaces,
                stamp_source_ipv6_address, initialize
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

        logger.debug('RegisterStampReflector RPC invoked. Request: %s', request)

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

        # Try to register the STAMP Session Reflector
        try:
            self.controller.add_stamp_reflector(
                node_id, grpc_ip, grpc_port, ip, udp_port, interfaces,
                stamp_source_ipv6_address, initialize
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

        # Try to unregister the STAMP node
        try:
            self.controller.unregister_stamp_node(node_id=request.node_id)
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

        # Try to initialize the STAMP node
        try:
            self.controller.init_stamp_node(node_id=request.node_id)
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

        # Reset the STAMP node
        try:
            self.controller.reset_stamp_node(node_id=request.node_id)
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

        interval = None
        if request.interval:
            interval = request.interval

        duration = None
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
            delay_measurement_mode = request.stamp_params.delay_measurement_mode

        session_reflector_mode = None
        if request.stamp_params.session_reflector_mode:
            session_reflector_mode = request.stamp_params.session_reflector_mode

        sender_source_ip = None
        if request.sender_source_ipv6_address:
            sender_source_ip = request.sender_source_ipv6_address

        reflector_source_ip = None
        if request.reflector_source_ipv6_address:
            reflector_source_ip = request.reflector_source_ipv6_address

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
                reflector_source_ip=reflector_source_ip, description=description
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
            # The node specified as STAMP sender is not a sender, return an error
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
            # The node specified as STAMP reflector is not a reflector, return an error
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

        # Try to start the STAMP Session
        try:
            self.controller.start_stamp_session(ssid=request.ssid)
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

        # Try to stop the STAMP Session
        try:
            self.controller.stop_stamp_session(ssid=request.ssid)
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

        # Try to destroy the STAMP Session
        try:
            self.controller.destroy_stamp_session(ssid=request.ssid)
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

        # Try to collect the results of the STAMP Session
        try:
            direct_path_results, return_path_results = \
                self.controller.get_stamp_results(
                    ssid=request.ssid,
                    fetch_results_from_stamp=True
            )
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
                    ssid=request.ssid)[0]
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
        res.measurement_type = controller_pb2.MeasurementType.MEASUREMENT_TYPE_DELAY
        res.measurement_direction = controller_pb2.MeasurementDirection.MEASUREMENT_DIRECTION_BOTH
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

        # Try to collect the results of the STAMP Session
        stamp_sessions = self.controller.get_measurement_sessions(ssid=ssid)

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
                sess.sender_source_ip = stamp_session.sender.stamp_source_ipv6_address
            sess.reflector_id = stamp_session.reflector.node_id
            sess.reflector_name = stamp_session.reflector.node_name
            if stamp_session.reflector.stamp_source_ipv6_address is not None:
                sess.reflector_source_ip = stamp_session.reflector.stamp_source_ipv6_address
            sess.interval = stamp_session.interval
            sess.stamp_params.auth_mode = stamp_session.auth_mode
            sess.stamp_params.key_chain = stamp_session.sender_key_chain
            sess.stamp_params.timestamp_format = stamp_session.sender_timestamp_format
            sess.stamp_params.packet_loss_type = stamp_session.packet_loss_type
            sess.stamp_params.delay_measurement_mode = stamp_session.delay_measurement_mode
            sess.stamp_params.session_reflector_mode = stamp_session.session_reflector_mode
            sess.direct_sidlist.segments.extend(stamp_session.sidlist)
            sess.return_sidlist.segments.extend(stamp_session.return_sidlist)
            sess.average_delay_direct_path = stamp_session.stamp_session_direct_path_results.mean_delay
            sess.average_delay_return_path = stamp_session.stamp_session_return_path_results.mean_delay

        # Set status code and return
        logger.debug('GetStampSessions RPC completed')
        reply.status = common_pb2.StatusCode.STATUS_CODE_SUCCESS
        return reply


def run_grpc_server(grpc_ip: str = None, grpc_port: int = DEFAULT_GRPC_PORT,
                    secure_mode=False):
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

    Returns
    -------
    None
    """

    # Create a Controller object
    controller = Controller()

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
