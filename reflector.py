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
# Implementation of a STAMP Session Reflector defined in RFC 8762
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
This module provides an implementation of a STAMP Session Reflector defined in
RFC 8762.
"""

from concurrent import futures
import argparse
import logging
import netifaces
import os
import socket

import grpc

import common_pb2
import stamp_reflector_pb2
import stamp_reflector_pb2_grpc

from scapy.arch.linux import L3PacketSocket
from scapy.sendrecv import AsyncSniffer

from utils import (
    NEXT_HEADER_IPV6_FIELD,
    NEXT_HEADER_SRH_FIELD,
    ROUTING_HEADER_PROTOCOL_NUMBER,
    UDP_DEST_PORT_FIELD,
    UDP_PROTOCOL_NUMBER,
    STAMPReflectorSession,
    AuthenticationMode,
    TimestampFormat,
    SessionReflectorMode,
    grpc_to_py_resolve_defaults,
    py_to_grpc
)
from libs import libstamp


# Default command-line arguments
DEFAULT_GRPC_IP = None
DEFAULT_GRPC_PORT = 12345

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
    datefmt='%m-%d %H:%M')

# Get the root logger
logger = logging.getLogger()


class STAMPSessionReflectorServicer(
        stamp_reflector_pb2_grpc.STAMPSessionReflectorService):
    """
    Provides methods that implement the functionalities of a STAMP Session
    Reflector.
    """

    def __init__(self):
        # Initialize super class STAMPSessionReflectorService
        super().__init__()
        # A dict containing information about the running STAMP Sessions
        self.stamp_sessions = {}
        # Reflector UDP port
        self.reflector_udp_port = None
        # Thread to receive the incoming STAMP Test packets
        self.stamp_packet_receiver = None
        # Socket used to send and receive STAMP packets
        self.reflector_socket = None
        # Auxiliary socket, used to support randomly chosen port numbers and
        # to prevent other applications from using the STAMP port
        self.auxiliary_socket = None
        # Interfaces on which the Reflector listens for STAMP packets
        self.stamp_interfaces = None
        # Is reflector initialized?
        self.is_initialized = False
        # IP address to be used as source IPv6 address of the STAMP Reply
        # packets. This parameter can be overridden by setting the
        # stamp_source_ipv6_address attribute in the STAMPSession
        # If it is None, the loopback IPv6 address will be used.
        self.stamp_source_ipv6_address = None

    def _reset(self):
        """
        Helper function used to reset and stop the Reflector.

        Returns
        -------
        success : bool
            True if reset performed sucessfully, False otherwise.
        """

        logger.info('Resetting STAMP Session-Reflector')

        # Prevent reset if some sessions exist
        if len(self.stamp_sessions) != 0:
            logger.error('Reset failed: STAMP Sessions exist')
            return False  # TODO raise an exception?

        # Stop and destroy the receive thread
        logger.info('Stopping receive thread')
        logger.info('Stopping sniffing...')
        self.stamp_packet_receiver.stop()
        logger.info('Destroying receive thread')
        self.stamp_packet_receiver = None

        # Remove ip6tables rule for STAMP packets
        rule_exists = os.system('ip6tables -C INPUT -p udp --dport {port} '
                                '-j DROP'
                                .format(port=self.reflector_udp_port)) == 0
        if rule_exists:
            logger.info('Clearing ip6tables rule for STAMP packets')
            os.system('ip6tables -D INPUT -p udp --dport {port} -j DROP'
                      .format(port=self.reflector_udp_port))
        else:
            logger.info('ip6tables rule for STAMP packets does not exist. '
                        'Skipping')

        # Clear the UDP port
        logger.info('Clearing port information')
        self.reflector_udp_port = None

        # Close the auxiliary UDP socket
        logger.info('Closing the auxiliary UDP socket')
        self.auxiliary_socket.close()
        self.auxiliary_socket = None

        # Close the Scapy socket
        logger.info('Closing the socket')
        self.reflector_socket.close()
        self.reflector_socket = None

        # Clear interface information
        logger.info('Clearing the interface information')
        self.stamp_interfaces = None

        # Clear "is_initialized" flag
        self.is_initialized = False

        # Success
        logger.info('Reset completed')
        return True

    def is_session_valid(self, ssid):
        """
        Check if a STAMP Session is valid.

        Parameters
        ----------
        ssid : int
            SSID of the STAMP Session to check.

        Returns
        -------
        is_session_valid : bool
            True if the STAMP Session is valid, False otherwise.
        """

        return ssid in self.stamp_sessions

    def is_session_running(self, ssid):
        """
        Check if a STAMP Session is running.

        Parameters
        ----------
        ssid : int
            SSID of the STAMP Session to check.

        Returns
        -------
        is_session_running : bool
            True if the STAMP Session is running, False otherwise.
        """

        return self.stamp_sessions[ssid].is_running

    def stamp_test_packet_received(self, packet):
        """
        Called when a STAMP Test packet is received: validate the received
         packet, generate a STAMP Test Reply packet and send it to the
         Session-Sender.

        Parameters
        ----------
        packet : scapy.packet.Packet
            The STAMP Test packet received from the Sender.

        Returns
        -------
        None.
        """

        logger.debug('STAMP Test packet received: \n\n%s',
                     packet.show(dump=True))

        # Parse the received STAMP Test packet
        stamp_test_packet = libstamp.parse_stamp_test_packet(packet)

        # Get the STAMP Session by SSID
        stamp_session = self.stamp_sessions.get(stamp_test_packet.ssid, None)

        # Validate the STAMP packet and drop the packet if it is not valid

        logger.debug('Validating STAMP Session, SSID: %d',
                     stamp_test_packet.ssid)

        # Drop STAMP packet if SSID does not correspond to any STAMP Session
        if stamp_session is None:
            logger.error('Received an invalid STAMP Test packet: '
                         'Session with SSID %d does not exists',
                         stamp_test_packet.ssid)
            return  # Drop the packet

        # Drop STAMP packet if the Session is not running
        if not stamp_session.is_running:
            logger.error('Received an invalid STAMP Test packet: '
                         'Session with SSID %d is not running',
                         stamp_test_packet.ssid)
            return  # Drop the packet

        # Get an IPv6 address to be used as source IPv6 address for the STAMP
        # packet.
        #
        # We support three methods (listed in order of preference):
        #    * stamp_source_ipv6_address specific for this STAMP Session
        #    * global stamp_source_ipv6_address
        #    * IPv6 address of the loopback interface
        #
        # We use the specific stamp_source_ipv6_address; if it is None, we use
        # the global stamp_source_ipv6_address; if it is None, we use the IPv6
        # address of the loopback interface
        logger.debug('Getting a valid STAMP Source IPv6 Address')
        if stamp_session.stamp_source_ipv6_address is not None:
            ipv6_addr = stamp_session.stamp_source_ipv6_address
            logger.debug('Using the STAMP Session specific IPv6 '
                         'address: {ipv6_addr}'.format(ipv6_addr=ipv6_addr))
        elif self.stamp_source_ipv6_address is not None:
            ipv6_addr = self.stamp_source_ipv6_address
            logger.debug('Using the STAMP Session global IPv6 '
                         'address: {ipv6_addr}'.format(ipv6_addr=ipv6_addr))
        else:
            loopback_iface = netifaces.ifaddresses('lo')
            ipv6_addr = loopback_iface[netifaces.AF_INET6][0]['addr']
            logger.debug('Using the loopback IPv6 address: {ipv6_addr}'
                         .format(ipv6_addr=ipv6_addr))

        # Sequence number depends on the Session Reflector Mode
        if stamp_session.session_reflector_mode == \
                SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS.value:
            # As explained in RFC 8762, in stateless mode:
            #    The STAMP Session-Reflector does not maintain test state and
            #    will use the value in the Sequence Number field in the
            #    received packet as the value for the Sequence Number field in
            #    the reflected packet.
            sequence_number = stamp_test_packet.sequence_number
        elif stamp_session.session_reflector_mode == \
                SessionReflectorMode.SESSION_REFLECTOR_MODE_STATEFUL.value:
            # As explained in RFC 8762, in stateful mode:
            #    STAMP Session-Reflector maintains the test state, thus
            #    allowing the Session-Sender to determine directionality of
            #    loss using the combination of gaps recognized in the Session
            #    Sender Sequence Number and Sequence Number fields,
            #    respectively.
            raise NotImplementedError  # Currently we don't support it

        # If the packet is valid, generate the STAMP Test Reply packet
        reply_packet = libstamp.generate_stamp_reply_packet(
            stamp_test_packet=packet,
            src_ip=ipv6_addr,
            dst_ip=stamp_test_packet.src_ip,
            src_udp_port=self.reflector_udp_port,
            dst_udp_port=stamp_test_packet.src_udp_port,
            sidlist=stamp_session.return_sidlist,
            ssid=stamp_test_packet.ssid,
            sequence_number=sequence_number,
            timestamp_format=stamp_session.timestamp_format,
        )

        # Send the reply packet to the Sender
        libstamp.send_stamp_packet(reply_packet, self.reflector_socket)

    def build_stamp_test_packets_sniffer(self):
        """
        Return a STAMP packets sniffer.

        Returns
        -------
        sniffer : scapy.sendrecv.AsyncSniffer
            Return an AsyncSniffer.
        """

        # Build a BPF filter expression to filter STAMP packets received
        stamp_filter = (
            '{next_header_ipv6_field} == {routing_header_protocol_number} && '
            '{next_header_srh_field} == {udp_protocol_number} && '
            '{udp_dest_port_field} == {stamp_port}'.format(
                next_header_ipv6_field=NEXT_HEADER_IPV6_FIELD,
                routing_header_protocol_number=ROUTING_HEADER_PROTOCOL_NUMBER,
                next_header_srh_field=NEXT_HEADER_SRH_FIELD,
                udp_protocol_number=UDP_PROTOCOL_NUMBER,
                udp_dest_port_field=UDP_DEST_PORT_FIELD,
                stamp_port=self.reflector_udp_port)
        )

        logging.debug('Creating AsyncSniffer, iface: {iface}, '
                      'filter: {filter}'.format(
                          iface=self.stamp_interfaces, filter=stamp_filter))

        # Create and return an AsyncSniffer
        sniffer = AsyncSniffer(
            iface=self.stamp_interfaces,
            filter=stamp_filter,
            prn=self.stamp_test_packet_received)
        return sniffer

    def Init(self, request, context):
        """RPC used to configure the Session Reflector."""

        logger.debug('Init RPC invoked. Request: %s', request)
        logger.info('Initializing STAMP Session-Reflector')

        # If already initialized, return an error
        if self.is_initialized:
            logger.error('Reflector node has been already initialized')
            return stamp_reflector_pb2.InitStampReflectorReply(
                status=common_pb2.StatusCode.STATUS_CODE_ALREADY_INITIALIZED,
                description='Reflector node has been already initialized')

        # Validate the UDP port provided
        logger.debug('Validating the provided UDP port: %d',
                     request.reflector_udp_port)
        if request.reflector_udp_port not in range(1, 65536):
            logger.error('Invalid UDP port %d', request.reflector_udp_port)
            return stamp_reflector_pb2.InitStampReflectorReply(
                status=common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT,
                description='Invalid UDP port {port}'
                            .format(port=request.reflector_udp_port))
        logger.debug('UDP port %d is valid', request.reflector_udp_port)

        # Extract the interface from the gRPC message
        # Interface is an optional argument; when omitted, we listen on all the
        # interfaces except loopback interface
        if len(request.interfaces) == 0:
            # Get all the interfaces
            self.stamp_interfaces = netifaces.interfaces()
            # We exclude the loopback interface to avoid problems
            # From the scapy documentation...
            #    The loopback interface is a very special interface. Packets
            #    going through it are not really assembled and disassembled.
            #    The kernel routes the packet to its destination while it is
            #    still stored an internal structure
            self.stamp_interfaces.remove('lo')
        else:
            # One or more interfaces provided in the gRPC message
            self.stamp_interfaces = list(request.interfaces)

        # Extract STAMP Source IPv6 address from the request message
        # This parameter is optional, therefore we leave it to None if it is
        # not provided
        if request.stamp_source_ipv6_address:
            self.stamp_source_ipv6_address = request.stamp_source_ipv6_address

        # Open a Scapy socket (L3PacketSocket) for sending and receiving STAMP
        # packets; under the hood, L3PacketSocket uses a AF_PACKET socket
        logger.debug('Creating a new reflector socket')
        self.reflector_socket = L3PacketSocket()

        # Open a UDP socket
        # UDP socket will not be used at all, but we need for two reasons:
        # - to reserve STAMP UDP port and prevent other applications from
        #   using it
        # - to implement a mechanism of randomly chosen UDP port; indeed, to
        #   get a random free UDP port we can bind a UDP socket to port 0
        #   (only on the STAMP Sender)
        logger.debug('Creating an auxiliary UDP socket')
        self.auxiliary_socket = socket.socket(
            socket.AF_INET6, socket.SOCK_DGRAM, 0)
        try:
            self.auxiliary_socket.bind(('::', request.reflector_udp_port))
        except OSError as err:
            logger.error('Cannot create UDP socket: %s', err)
            # Reset the node
            self._reset()
            # Return an error to the Controller
            return stamp_reflector_pb2.InitStampReflectorReply(
                status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
                description='Cannot create UDP socket: {err}'.format(err=err))
        logger.info('Socket configured')

        # Extract the UDP port (this also works if we are chosing the port
        # randomly)
        logger.debug('Configuring UDP port %d',
                     self.auxiliary_socket.getsockname()[1])
        self.reflector_udp_port = self.auxiliary_socket.getsockname()[1]
        logger.info('Using UDP port %d', self.reflector_udp_port)

        # Set an ip6tables rule to drop STAMP packets after delivering them
        # to Scapy; this is required to avoid ICMP error messages when the
        # STAMP packets are delivered to a non-existing UDP port
        rule_exists = os.system('ip6tables -C INPUT -p udp --dport {port} '
                                '-j DROP'
                                .format(port=self.reflector_udp_port)) == 0
        if not rule_exists:
            logger.info('Setting ip6tables rule for STAMP packets')
            os.system('ip6tables -I INPUT -p udp --dport {port} -j DROP'
                      .format(port=self.reflector_udp_port))
        else:
            logger.warning('ip6tables rule for STAMP packets already exist. '
                           'Skipping')

        # Create and start a new thread to listen for incoming STAMP Test
        # Reply packets
        logger.info('Starting receive thread')
        logger.info('Start sniffing...')
        self.stamp_packet_receiver = self.build_stamp_test_packets_sniffer()
        self.stamp_packet_receiver.start()

        # Set "is_initialized" flag
        self.is_initialized = True

        # Return with success status code
        logger.info('Initialization completed')
        logger.debug('Init RPC completed')
        return stamp_reflector_pb2.InitStampReflectorReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def Reset(self, request, context):
        """RPC used to reset the Session Reflector."""

        logger.debug('Reset RPC invoked. Request: %s', request)
        logger.info('Attempting to reset STAMP node')

        # Reset the Session Reflector and check the return value
        # If False is returned, the Reset command has failed and we return an
        # error to the controller
        if not self._reset():
            logger.error('Reset RPC failed')
            return stamp_reflector_pb2.ResetStampReflectorReply(
                status=common_pb2.StatusCode.STATUS_CODE_RESET_FAILED,
                description='Cannot execute Reset command: One or more STAMP '
                            'Sessions exist. Destroy all STAMP Sessions '
                            'before resetting the node.')

        # Return with success status code
        logger.info('Reset completed')
        logger.debug('Reset RPC completed')
        return stamp_reflector_pb2.ResetStampReflectorReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def CreateStampSession(self, request, context):
        """RPC used to create a new STAMP Session."""

        logger.debug('CreateStampSession RPC invoked. Request: %s', request)
        logger.info('Creating new STAMP Session, SSID %d', request.ssid)

        # If Reflector is not initialized, return an error
        if not self.is_initialized:
            logger.error('Reflector node is not initialized')
            return stamp_reflector_pb2.CreateStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
                description='Reflector node is not initialized')

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get Session, SSID %d', request.ssid)
        session = self.stamp_sessions.get(request.ssid, None)

        # If the session already exists, return an error
        logger.debug('Validate SSID %d', request.ssid)
        if session is not None:
            logger.error('A session with SSID %d already exists',
                         request.ssid)
            return stamp_reflector_pb2.CreateStampSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_EXISTS,
                description='A session with SSID {ssid} already exists'
                            .format(ssid=request.ssid))

        # Extract STAMP Source IPv6 address from the request message
        # This parameter is optional, therefore we set it to None if it is
        # not provided
        stamp_source_ipv6_address = None
        if request.stamp_source_ipv6_address:
            stamp_source_ipv6_address = request.stamp_source_ipv6_address

        # Parse optional parameters
        # If an optional parameter has not been set, we use the default value
        auth_mode = grpc_to_py_resolve_defaults(
            AuthenticationMode, request.stamp_params.auth_mode)
        key_chain = request.stamp_params.key_chain
        timestamp_format = grpc_to_py_resolve_defaults(
            TimestampFormat, request.stamp_params.timestamp_format)
        session_reflector_mode = grpc_to_py_resolve_defaults(
            SessionReflectorMode, request.stamp_params.session_reflector_mode)

        # Check Authentication Mode
        if auth_mode == AuthenticationMode.AUTHENTICATION_MODE_HMAC_SHA_256:
            logger.fatal('Authenticated Mode is not implemented')
            raise NotImplementedError

        # Check Session Reflector Mode
        if session_reflector_mode == \
                SessionReflectorMode.SESSION_REFLECTOR_MODE_STATEFUL:
            logger.fatal('Stateful Mode is not implemented')
            raise NotImplementedError

        # Initialize a new STAMP Session
        logger.debug('Initializing a new STAMP Session')
        stamp_session = STAMPReflectorSession(
            ssid=request.ssid,
            reflector_udp_port=request.stamp_params.reflector_udp_port,
            return_sidlist=list(request.return_sidlist.segments),
            auth_mode=auth_mode, key_chain=key_chain,
            timestamp_format=timestamp_format,
            session_reflector_mode=session_reflector_mode,
            stamp_source_ipv6_address=stamp_source_ipv6_address
        )
        logger.debug('STAMP Session initialized: SSID %d', request.ssid)

        # Add the STAMP session to the STAMP sessions dict
        self.stamp_sessions[request.ssid] = stamp_session

        # Create the reply message
        reply = stamp_reflector_pb2.CreateStampReflectorSessionReply()

        # Fill the reply with the STAMP parameters
        # We report the STAMP parameters to the controller to inform it about
        # the values chosen by the Reflector for the optional parameters
        reply.stamp_params.reflector_udp_port = \
            request.stamp_params.reflector_udp_port
        reply.stamp_params.auth_mode = py_to_grpc(
            AuthenticationMode, auth_mode)
        reply.stamp_params.key_chain = key_chain
        reply.stamp_params.timestamp_format = py_to_grpc(
            TimestampFormat, timestamp_format)
        reply.stamp_params.session_reflector_mode = py_to_grpc(
            SessionReflectorMode, session_reflector_mode)

        # Set success status code
        reply.status = common_pb2.StatusCode.STATUS_CODE_SUCCESS

        # Return with success status code
        logger.info('STAMP Session (SSID %d) created', request.ssid)
        logger.debug('CreateStampSession RPC completed')
        return reply

    def StartStampSession(self, request, context):
        """RPC used to start a STAMP Session."""

        logger.debug('StartStampSession RPC invoked. Request: %s', request)
        logger.info('Starting STAMP Session, SSID %d', request.ssid)

        # If Reflector is not initialized, return an error
        if not self.is_initialized:
            logger.error('Reflector node is not initialized')
            return stamp_reflector_pb2.StartStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
                description='Reflector node is not initialized')

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get Session, SSID %d', request.ssid)
        session = self.stamp_sessions[request.ssid]

        # If the session does not exist, return an error
        logger.debug('Validating SSID %d', request.ssid)
        if session is None:
            logger.error('SSID %d not found', request.ssid)
            return stamp_reflector_pb2.StartStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
                description='SSID {ssid} not found'.format(ssid=request.ssid))

        # If the session is already running, return an error
        logger.debug('Checking if session is running, SSID %d', request.ssid)
        if session.is_running:
            logger.error('Cannot start STAMP Session (SSID %d): Session '
                         'already running', request.ssid)
            return stamp_reflector_pb2.StartStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_RUNNING,
                description='STAMP Session (SSID {ssid}) already running'
                .format(ssid=request.ssid))

        # Set the flag "started"
        session.set_started()

        # Return with success status code
        logger.info('STAMP Session (SSID %d) started', request.ssid)
        logger.debug('StartStampSessionReply RPC completed')
        return stamp_reflector_pb2.StartStampReflectorSessionReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def StopStampSession(self, request, context):
        """RPC used to stop a running STAMP Session."""

        logger.debug('StopStampSession RPC invoked. Request: %s', request)
        logger.info('Stopping STAMP Session, SSID %d', request.ssid)

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get STAMP Session, SSID %d', request.ssid)
        session = self.stamp_sessions.get(request.ssid, None)

        # If the session does not exist, return an error
        logger.debug('Validating SSID %d', request.ssid)
        if session is None:
            logger.error('SSID %d not found', request.ssid)
            return stamp_reflector_pb2.StopStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
                description='SSID {ssid} not found'.format(ssid=request.ssid))

        # If the session is not running, return an error
        logger.debug('Checking if session is running, SSID %d', request.ssid)
        if not session.is_running:
            logger.error('Cannot stop STAMP Session (SSID %d): Session '
                         'not running', request.ssid)
            return stamp_reflector_pb2.StopStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_RUNNING,
                description='STAMP Session (SSID {ssid}) is not running'
                .format(ssid=request.ssid))

        # Clear the flag "started"
        session.clear_started()

        # Return with success status code
        logger.info('STAMP Session (SSID %d) stopped', request.ssid)
        logger.debug('StopStampSession RPC completed')
        return stamp_reflector_pb2.StopStampReflectorSessionReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

    def DestroyStampSession(self, request, context):
        """RPC used to destroy an existing STAMP Session."""

        logger.debug('DestroyStampSession RPC invoked. Request: %s', request)
        logger.info('Destroying STAMP Session, SSID %d', request.ssid)

        # If Reflector is not initialized, return an error
        if not self.is_initialized:
            logger.error('Reflector node is not initialized')
            return stamp_reflector_pb2.DestroyStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
                description='Reflector node is not initialized')

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get STAMP Session, SSID %d', request.ssid)
        session = self.stamp_sessions.get(request.ssid, None)

        # If the session does not exist, return an error
        logger.debug('Validating SSID %d', request.ssid)
        if session is None:
            logger.error('SSID %d not found', request.ssid)
            return stamp_reflector_pb2.DestroyStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
                description='SSID {ssid} not found'.format(ssid=request.ssid))

        # If the session is running, we cannot destory it and we need to
        # return an error
        logger.debug('Checking if session is running, SSID %d', request.ssid)
        if session.is_running:
            logger.error('Cannot destroy STAMP Session (SSID %d): Session '
                         'is currently running', request.ssid)
            return stamp_reflector_pb2.DestroyStampReflectorSessionReply(
                status=common_pb2.StatusCode.STATUS_CODE_SESSION_RUNNING,
                description='STAMP Session (SSID {ssid}) is running'
                .format(ssid=request.ssid))

        logger.debug('Removing Session with SSID %d', request.ssid)

        # Remove the STAMP session from the list of existing sessions
        del self.stamp_sessions[request.ssid]

        # Return with success status code
        logger.info('STAMP Session (SSID %d) destroyed', request.ssid)
        logger.debug('DestroyStampSession RPC completed')
        return stamp_reflector_pb2.DestroyStampReflectorSessionReply(
            status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)


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

    # Create the gRPC server
    logger.debug('Creating the gRPC server')
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    stamp_reflector_pb2_grpc \
        .add_STAMPSessionReflectorServiceServicer_to_server(
            STAMPSessionReflectorServicer(), server)

    # Add secure or insecure port, depending on the "secure_mode" chosen
    if secure_mode:
        logger.fatal('Secure mode not yet implemented')
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
        description='STAMP Session Reflector implementation.')
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

# TODO Sender e Reflector separati dal servicer

# TODO spostare funzioni specifiche per sender e reflector da utils a classi
# specifiche

# TODO aggiungere is started ai proto?
