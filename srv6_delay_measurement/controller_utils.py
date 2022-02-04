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
# Utilities for SDN Controller
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#

import logging
import time


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
    sender_udp_port : int
        UDP port used by STAMP Sender. If it is None, the Sender port will be
        chosen randomly.
    reflector_udp_port : int
        UDP port used by STAMP Reflector. If it is None, the Sender port will
        be chosen randomly.
    node_name : str
        A human-friendly name for the STAMP node.
    interfaces : list, optional
        The list of the interfaces on which the STAMP node will listen for
         STAMP packets. If this parameter is None, the node will listen on all
         the interfaces (default is None).
    grpc_channel_sender : grpc._channel.Channel
        gRPC channel to the node (sender).
    grpc_channel_reflector : grpc._channel.Channel
        gRPC channel to the node (reflector).
    grpc_stub_sender : :object:
        gRPC stub to interact with the node (sender).
    grpc_stub_reflector : :object:
        gRPC stub to interact with the node (reflector).
    stamp_source_ipv6_address : str
        The IPv6 address to be used as source IPv6 address of the STAMP
            packets. This can be overridden by providing a IPv6 address to the
            create_stamp_session method. If None, the Sender/Reflector will
            use the loopback IPv6 address as STAMP Source Address.
    is_sender_initialized : bool
        Flag indicating whether the node has been initialized or not.
    is_reflector_initialized : bool
        Flag indicating whether the node has been initialized or not.

    Methods
    -------
    """

    def __init__(self, node_id, grpc_ip, grpc_port, ip, sender_udp_port=None,
                 reflector_udp_port=None, node_name=None,
                 interfaces=None, stamp_source_ipv6_address=None,
                 is_sender=False, is_reflector=False):
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
        sender_udp_port : int, optional
            UDP port used by STAMP Sender. If it is None, the Sender port will
            be chosen randomly.
        reflector_udp_port : int, optional
            UDP port used by STAMP Reflector. If it is None, the Reflector port
            will be chosen randomly.
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
        self.grpc_channel_sender = None
        self.grpc_stub_sender = None
        self.grpc_channel_reflector = None
        self.grpc_stub_reflector = None
        # Flag indicating whether the node has been initialized or not
        self.is_sender_initialized = False
        self.is_reflector_initialized = False
        # Set the UDP port of the Sender
        self.sender_udp_port = sender_udp_port
        # Set the UDP port of the Reflector
        self.reflector_udp_port = reflector_udp_port
        # Is Sender?
        self.is_sender = is_sender
        # Is Reflector?
        self.is_reflector = is_reflector
        # Number of STAMP Sessions on the node
        self.sessions_count = 0

    def is_stamp_sender(self):
        return self.is_sender

    def is_stamp_reflector(self):
        return self.is_reflector


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
    sender : controller.STAMPNode
        An object representing the STAMP Session Sender.
    reflector : controller.STAMPNode
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
                 store_individual_delays=False, duration=0):
        """
        Constructs all the necessary attributes for the STAMP Reflector object.

        Parameters
        ----------
        ssid : int
            16-bit Segment Session Identifier (SSID) of the STAMP Session.
        description : str
            A string which describes the STAMP Session.
        sender : controller.STAMPNode
            An object representing the STAMP Session Sender.
        reflector : controller.STAMPNode
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
        duration : int, optional
            Duration of the STAMP Session in seconds. 0 means endless session
            (default: 0).
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
        # Duration of the STAMP Session (in seconds)
        self.duration = duration


def compute_packet_delay(tx_timestamp, rx_timestamp):
    """
    Compute the delay (in milliseconds) of a STAMP packet (either Test or
    Reply packet).

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

    # Return the delay in milliseconds
    return (rx_timestamp - tx_timestamp) * 1000


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
