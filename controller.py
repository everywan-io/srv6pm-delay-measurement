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

import logging

import grpc

import common_pb2
from exceptions import CreateSTAMPSessionError, DestroySTAMPSessionError, GetSTAMPResultsError, InitSTAMPNodeError, InvalidStampNodeError, NodeIdAlreadyExistsError, NodeIdNotFoundError, NodeInitializedError, NodeNotInitializedError, NotAStampReflectorError, NotAStampSenderError, ResetSTAMPNodeError, StartSTAMPSessionError, StopSTAMPSessionError
import stamp_reflector_pb2
import stamp_reflector_pb2_grpc
import stamp_sender_pb2
import stamp_sender_pb2_grpc

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
    interfaces : list, optional
        The list of the interfaces on which the STAMP node will listen for
         STAMP packets. If this parameter is None, the node will listen on all
         the interfaces (default is None).
    grpc_channel : grpc._channel.Channel
        gRPC channel to the node.
    grpc_stub : # TODO
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

    def __init__(self, node_id, grpc_ip, grpc_port, ip, interfaces=None,
                 stamp_source_ipv6_address=None):
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
        self.interfaces = interfaces
        self.stamp_source_ipv6_address = stamp_source_ipv6_address
        # gRPC Channel and Stub are initially empty
        # They will be set when the STAMP node is initialized and a gRPC
        # connection to the node is established
        self.grpc_channel = None
        self.grpc_stub = None
        # Flag indicating whether the node has been initialized or not
        self.is_initialized = False

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
                 interfaces=None, stamp_source_ipv6_address=None):
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
        super().__init__(node_id, grpc_ip, grpc_port, ip, interfaces,
                         stamp_source_ipv6_address)
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
                 interfaces=None, stamp_source_ipv6_address=None):
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
        super().__init__(node_id, grpc_ip, grpc_port, ip, interfaces,
                         stamp_source_ipv6_address)
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

    def __init__(self, ssid,  sender, reflector, sidlist, return_sidlist,
                 interval, auth_mode, sender_key_chain, reflector_key_chain,
                 sender_timestamp_format, reflector_timestamp_format,
                 packet_loss_type, delay_measurement_mode,
                 session_reflector_mode, store_individual_delays=False):
        """
        Constructs all the necessary attributes for the STAMP Reflector object.

        Parameters
        ----------
        ssid : int
            16-bit Segment Session Identifier (SSID) of the STAMP Session.
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
            Define whether to store the individual delays or not (default False).
        """

        # Set STAMP session parameters
        self.ssid = ssid
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
    stub : # TODO?
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
    stub : # TODO?
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
            Define whether to store the individual delays or not (default False).
        """

        # Initialize all the attributes
        self.ssid = ssid
        self.store_individual_delays = store_individual_delays
        self.delays = list()
        self.mean_delay = 0.0
        self.count_packets = 0

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

        # Increase packets count
        self.count_packets += 1
        # Store the new delay, eventually
        if self.store_individual_delays:
            self.delays.add(new_delay)
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
    self.stamp_sessions : dict
        Map the SSID to the corresponding STAMPSession object

    Methods
    -------
    add_stamp_sender(node_id, udp_port=None)
        Add a STAMP Sender to the Controller inventory.
    add_stamp_reflector(node_id, ip, udp_port)
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
        Get the results collected by the STAMP Sender for the STAMP Session
         identified by the SSID.
    compute_jitter():
        # TODO
    """

    def __init__(self):
        """
        Constructs all the necessary attributes for the Controller object.
        """

        # Last used STAMP Session Identifier (SSID)
        self.last_ssid = -1
        # Pool of SSID allocated to STAMP Sessions terminated
        # These can be reused for other STAMP Sessions
        self.reusable_ssid = set()
        # Dict mapping node node_id to STAMPNode instance
        self.stamp_nodes = dict()
        # STAMP Sessions
        self.stamp_sessions = dict()

    def add_stamp_sender(self, node_id, grpc_ip, grpc_port, ip, udp_port=None,
                         interfaces=None, stamp_source_ipv6_address=None):
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

        Raises
        ------
        NodeIdAlreadyExistsError
            If `node_id` is already used.
        """

        # Check if node_id is already taken
        if self.stamp_nodes.get(node_id, None) is not None:
            raise NodeIdAlreadyExistsError
        # Create a STAMP Sender object and store it
        node = STAMPSender(
            node_id=node_id, grpc_ip=grpc_ip, grpc_port=grpc_port, ip=ip,
            udp_port=udp_port, interfaces=interfaces,
            stamp_source_ipv6_address=stamp_source_ipv6_address)
        self.stamp_nodes[node_id] = node

    def add_stamp_reflector(self, node_id, grpc_ip, grpc_port, ip, udp_port,
                            interfaces=None, stamp_source_ipv6_address=None):
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

        Raises
        ------
        NodeIdAlreadyExistsError
            If `node_id` is already used.
        """

        # Check if node_id is already taken
        if self.stamp_nodes.get(node_id, None) is not None:
            raise NodeIdAlreadyExistsError
        # Create a STAMP Sender object and store it
        node = STAMPReflector(
            node_id=node_id, grpc_ip=grpc_ip, grpc_port=grpc_port, ip=ip,
            udp_port=udp_port, interfaces=interfaces,
            stamp_source_ipv6_address=stamp_source_ipv6_address)
        self.stamp_nodes[node_id] = node

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

        # Retrieve the node information from the dict of STAMP nodes
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        if not node.is_stamp_sender():
            raise NotAStampSenderError

        # Check if the node has been already initialized
        if node.is_initialized:
            raise NodeInitializedError

        # Establish a gRPC connection to the Sender
        channel, stub = get_grpc_channel_sender(ip=node.grpc_ip,
                                                port=node.grpc_port)

        # Prepare the gRPC request message
        request = stamp_sender_pb2.InitStampSenderRequest()
        request.sender_udp_port = node.udp_port
        request.interfaces.extend(node.interfaces)
        if node.stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = node.stamp_source_ipv6_address

        # Invoke the Init RPC
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

        # Retrieve the node information from the dict of STAMP nodes
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Reflector
        if not node.is_stamp_reflector():
            raise NotAStampReflectorError

        # Check if the node has been already initialized
        if node.is_initialized:
            raise NodeInitializedError

        # Establish a gRPC connection to the Reflector
        channel, stub = get_grpc_channel_reflector(ip=node.grpc_ip,
                                                   port=node.grpc_port)

        # Prepare the gRPC request message
        request = stamp_reflector_pb2.InitStampReflectorRequest()
        request.reflector_udp_port = node.udp_port
        request.interfaces.extend(node.interfaces)
        if node.stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = node.stamp_source_ipv6_address

        # Invoke Init RPC
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
        NotAStampReflectorError
            If node identified by `node_id` is not a STAMP Reflector.
        InvalidStampNodeError
            If node is neither a STAMP Sender nor a STAMP Reflector.
        """

        # Retrieve the node information from the dict of STAMP nodes
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            raise NodeIdNotFoundError

        # Check if the node is a STAMP Sender or a STAMP Reflector
        if node.is_stamp_sender():
            return self.init_sender(node_id)
        if node.is_stamp_reflector():
            return self.init_reflector(node_id)

        # Node is neither a sender nor a reflector
        raise InvalidStampNodeError

    def reset_stamp_sender(self, node_id):
        """
        Reset a STAMP Sender and tear down the gRPC
         connection.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Reflector to be initialized.

        Returns
        None
        """

        # Retrieve the node information from the dict of STAMP nodes
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        if not node.is_stamp_sender():
            raise NotAStampSenderError

        # Check if the node has been initialized
        if not node.is_initialized:
            raise NodeNotInitializedError

        # Prepare the request message
        request = stamp_sender_pb2.ResetStampSenderRequest()

        # Invoke the Reset RPC
        reply = node.grpc_stub.Reset(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot reset STAMP Node: %s', reply.description)
            # Raise an exception
            raise ResetSTAMPNodeError(reply.description)

        # Tear down the gRPC channel to the node
        node.grpc_channel.close()
        node.grpc_channel = None
        node.grpc_stub = None

    def reset_stamp_reflector(self, node_id):
        """
        Reset a STAMP Reflector and tear down the gRPC
         connection.

        Parameters
        ----------
        node_id : str
            The identifier of the STAMP Reflector to be initialized.

        Returns
        None
        """

        # Retrieve the node information from the dict of STAMP nodes
        node = self.stamp_nodes.get(node_id, None)
        if node is None:
            raise NodeIdNotFoundError

        # Check that the node is a STAMP Sender
        if not node.is_stamp_reflector():
            raise NotAStampReflectorError

        # Check if the node has been initialized
        if not node.is_initialized:
            raise NodeNotInitializedError

        # Prepare the request message
        request = stamp_reflector_pb2.ResetStampReflectorRequest()

        # Invoke the Reset RPC
        reply = node.grpc_stub.Reset(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot reset STAMP Node: %s', reply.description)
            # Raise an exception
            raise ResetSTAMPNodeError(reply.description)

        # Tear down the gRPC channel to the node
        node.grpc_channel.close()
        node.grpc_channel = None
        node.grpc_stub = None

    def _create_stamp_sender_session(self, ssid, sender, reflector,
                                     sidlist=[], interval=10, auth_mode=None,
                                     key_chain=None, timestamp_format=None,
                                     packet_loss_type=None,
                                     delay_measurement_mode=None):
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

        Returns
        -------
        The STAMP Sender Reply received from the Sender
        """

        # Create a request message
        request = stamp_sender_pb2.CreateStampSenderSessionRequest()  # TODO

        # Fill the request message
        request.ssid = ssid
        request.sidlist.segments.extend(sidlist)
        request.interval = interval
        # request.stamp_params.sender_udp_port = sender.udp_port  # TODO togliere?
        request.stamp_params.reflector_ip = reflector.ip
        request.stamp_params.reflector_udp_port = reflector.udp_port

        # Fill in optional parameters

        if auth_mode is not None:
            request.stamp_params.auth_mode = auth_mode

        # request.stamp_params.key_chain = ...  # Not used in unauth mode

        if timestamp_format is not None:
            request.stamp_params.timestamp_format = timestamp_format

        # request.stamp_params.packet_loss_type = ...  # Not used for delay

        if delay_measurement_mode is not None:
            request.stamp_params.delay_measurement_mode = \
                delay_measurement_mode

        # Invoke the RPC
        reply = sender.grpc_stub.CreateStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot create STAMP Session: %s', reply.description)
            # Raise an exception
            raise CreateSTAMPSessionError(reply.description)

        # Return the reply
        return reply

    def _create_stamp_reflector_session(self, ssid, sender, reflector,
                                        return_sidlist, auth_mode=None,
                                        key_chain=None, timestamp_format=None,
                                        session_reflector_mode=None):
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

        Returns
        -------
        The STAMP Reflector Reply received from the Reflector.
        """

        # Create a request message
        request = stamp_reflector_pb2.CreateStampReflectorSessionRequest()

        # Fill the request message
        request.ssid = ssid
        request.return_sidlist.segments.extend(return_sidlist)
        request.stamp_params.reflector_udp_port = reflector.udp_port

        if auth_mode is not None:
            request.stamp_params.auth_mode = auth_mode

        # request.stamp_params.key_chain = ...  # Not used in unauth mode

        if timestamp_format is not None:
            request.stamp_params.timestamp_format = timestamp_format

        if session_reflector_mode is not None:
            request.stamp_params.session_reflector_mode = \
                session_reflector_mode

        # Invoke the RPC
        reply = reflector.grpc_stub.CreateStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error('Cannot create STAMP Session: %s', reply.description)
            # Raise an exception
            raise CreateSTAMPSessionError(reply.description)

        # Return the reply
        return reply

    def create_stamp_session(self, sender_id, reflector_id=None, sidlist=[],
                             return_sidlist=[], interval=10, auth_mode=None,
                             key_chain=None, timestamp_format=None,
                             packet_loss_type=None,
                             delay_measurement_mode=None,
                             session_reflector_mode=None,
                             store_individual_delays=False):
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

        Returns
        -------
        ssid : int
            The SSID allocated to the STAMP Session.
        """

        # Retrieve the node information from the dict of STAMP nodes
        # TODO gestire caso se non esiste
        sender = self.stamp_nodes[sender_id]
        # TODO check if it is a stamp reflector
        # TODO add is_initialized al nodo per verificare se è stato initislized

        # Retrieve the node information from the dict of STAMP nodes
        # TODO gestire caso se non esiste
        reflector = self.stamp_nodes[reflector_id]
        # TODO check if it is a stamp reflector
        # TODO add is_initialized al nodo per verificare se è stato initislized

        # Check if the STAMP Sender has been initialized
        if not sender.is_initialized:
            raise NodeNotInitializedError

        # Check if the STAMP Reflector has been initialized
        if not reflector.is_initialized:
            raise NodeNotInitializedError

        # Create a request message
        request = stamp_sender_pb2.CreateStampSenderSessionRequest()  # TODO

        # Pick a SSID from the reusable SSIDs pool
        # If the pool is empty, we take a new SSID
        if len(self.reusable_ssid) > 0:
            ssid = self.reusable_ssid.pop()
        else:
            ssid = self.last_ssid + 1
            self.last_ssid += 1

        # Process optional arguments

        if auth_mode == 'unauthenticated':
            auth_mode = (common_pb2.AuthenticationMode
                         .AUTHENTICATION_MODE_UNAUTHENTICATED)
        elif auth_mode == 'hmac-sha-256':
            auth_mode = (common_pb2.AuthenticationMode
                         .AUTHENTICATION_MODE_HMAC_SHA_256)

        # request.stamp_params.key_chain = ...  # Not used in unauth mode

        if timestamp_format == 'ntp':
            request.stamp_params.timestamp_format = \
                common_pb2.TimestampFormat.TIMESTAMP_FORMAT_NTP
        elif timestamp_format == 'ptp':
            request.stamp_params.timestamp_format = \
                common_pb2.TimestampFormat.TIMESTAMP_FORMAT_PTPv2

        if packet_loss_type == 'round-trip':
            request.stamp_params.packet_loss_type = \
                common_pb2.PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP
        elif packet_loss_type == 'near-end':
            request.stamp_params.packet_loss_type = \
                common_pb2.PacketLossType.PACKET_LOSS_TYPE_NEAR_END
        elif packet_loss_type == 'far-end':
            request.stamp_params.packet_loss_type = \
                common_pb2.PacketLossType.PACKET_LOSS_TYPE_FAR_END

        if delay_measurement_mode == 'one-way':
            request.stamp_params.delay_measurement_mode = \
                common_pb2.DelayMeasurementMode.DELAY_MEASUREMENT_MODE_ONE_WAY
        elif delay_measurement_mode == 'two-way':
            request.stamp_params.delay_measurement_mode = \
                common_pb2.DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY
        elif delay_measurement_mode == 'loopback':
            request.stamp_params.delay_measurement_mode = \
                common_pb2.DelayMeasurementMode.DELAY_MEASUREMENT_MODE_LOOPBACK

        if session_reflector_mode == 'stateless':
            request.stamp_params.session_reflector_mode = \
                (common_pb2
                 .DelayMeasurementMode.SESSION_REFLECTOR_MODE_STATELESS)
        elif session_reflector_mode == 'stateful':
            request.stamp_params.session_reflector_mode = \
                common_pb2.DelayMeasurementMode.SESSION_REFLECTOR_MODE_STATEFUL

        # Create STAMP Session on the Sender
        sender_reply = self._create_stamp_sender_session(
            ssid, sender, reflector, sidlist, interval)

        # Create STAMP Session on the Reflector
        if reflector is not None:
            reflector_reply = self._create_stamp_reflector_session(
                ssid, sender, reflector, return_sidlist)

        # Extract the STAMP parameters from the gRPC request
        # Both the Sender and the Reflector report the STAMP parameters to the
        # controller to inform it about the values chosen for the optional
        # parameters

        # sender_udp_port = sender_reply.sender_udp_port  # TODO rimuovere?
        reflector_ip = sender_reply.stamp_params.reflector_ip
        sender_key_chain = sender_reply.stamp_params.key_chain
        sender_timestamp_format = sender_reply.stamp_params.timestamp_format
        packet_loss_type = sender_reply.stamp_params.packet_loss_type
        delay_measurement_mode = sender_reply.stamp_params.delay_measurement_mode

        reflector_key_chain = reflector_reply.stamp_params.key_chain
        reflector_timestamp_format = reflector_reply.stamp_params.timestamp_format
        session_reflector_mode = reflector_reply.stamp_params.session_reflector_mode

        # Sender and Reflector "reflector_udp_port" must be equal
        if sender_reply.stamp_params.reflector_udp_port != \
                reflector_reply.stamp_params.reflector_udp_port:
            logger.fatal('BUG - reflector_udp_port must be equal both on the '
                         'Sender and the Reflector')
            exit(-1)

        reflector_udp_port = sender_reply.stamp_params.reflector_udp_port

        # Sender and Reflector auth mode must be equal
        if sender_reply.stamp_params.auth_mode != reflector_reply.stamp_params.auth_mode:
            logger.fatal('BUG - Sender auth mode and Reflector auth mode '
                         'must be equal')
            exit(-1)

        auth_mode = sender_reply.stamp_params.auth_mode

        # Create a STAMP Session object
        stamp_session = STAMPSession(
            ssid=ssid,
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

        # Return the SSID allocated for the STAMP session
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

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            return  # TODO raise exception?

        # Start STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
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
        request = stamp_sender_pb2.StartStampSenderSessionRequest()
        request.ssid = ssid
        reply = stamp_session.sender.grpc_stub.StartStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot start STAMP Session on Sender: %s', reply.description)
            return
            # Raise an exception
            raise StartSTAMPSessionError(reply.description)

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

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            return  # TODO raise exception?

        # Stop STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
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
        request = stamp_sender_pb2.StopStampSenderSessionRequest()
        request.ssid = ssid
        reply = stamp_session.sender.grpc_stub.StopStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot stop STAMP Session on Sender: %s', reply.description)
            # Raise an exception
            raise StopSTAMPSessionError(reply.description)

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

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            return  # TODO raise exception?

        # Destroy STAMP Session on the Reflector, if any
        if stamp_session.reflector is not None:
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
        request = stamp_sender_pb2.DestroyStampSenderSessionRequest()
        request.ssid = ssid
        reply = stamp_session.sender.grpc_stub.DestroyStampSession(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot destroy STAMP Session on Sender: %s',
                reply.description)
            # Raise an exception
            raise DestroySTAMPSessionError(reply.description)

        del self.stamp_sessions[ssid]

    def get_stamp_results(self, ssid):
        """
        Get the results collected by the STAMP Sender for the STAMP Session
         identified by the SSID.

        Parameters
        ----------
        ssid : int
            The 16-bit STAMP Session Identifier (SSID)

        Results
        -------
        # TODO
        """

        # Get STAMP Session; if it does not exist, return an error
        stamp_session = self.stamp_sessions.get(ssid, None)
        if stamp_session is None:
            logger.error('Session %d does not exist', ssid)
            return  # TODO raise exception?

        # Get results of the STAMP Session
        request = stamp_sender_pb2.GetStampSessionResultsRequest()
        request.ssid = ssid
        reply = stamp_session.sender.grpc_stub.GetStampSessionResults(request)
        if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
            logger.error(
                'Cannot collect STAMP Session results (SSID %d): %s',
                request.ssid, reply.description)
            # Raise an exception
            raise GetSTAMPResultsError(reply.description)

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

            logger.info('\n*********')   # TODO
            logger.info('Delay measured for the direct path: %f',
                        delay_direct_path)
            logger.info('Delay measured for the return path: %f',
                        delay_return_path)
            logger.info('Mean delay for the direct path: %f',
                        stamp_session.stamp_session_direct_path_results.mean_delay)   # TODO
            logger.info('Mean delay for the return path: %f',
                        stamp_session.stamp_session_return_path_results.mean_delay)   # TODO
            logger.info('*********\n')   # TODO

# TODO se il pacchetto si parde seq num non deve incrementare? verificare!
        # TODO

        # TODO reuse ssid

        # TODO strace

    def compute_jitter(self):
        pass  # TODO


# TODO Aprire e salvare stub e canali sender e reflector
# TODO aggiornare porta random sender con porta effettiva

# TODO aggiungere async test + duration


# TODO verificare se sono corretti i risultati

# FIXME a volte valori negativi
