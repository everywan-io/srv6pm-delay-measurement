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
# Northbound APIs utils.
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
Implementation of a Northbound interface.
"""

from socket import AF_INET, AF_INET6
import grpc
import logging
import sys

from pkg_resources import resource_filename
sys.path.append(resource_filename(__name__, 'commons/protos/srv6pm/gen_py/'))

import common_pb2
import controller_pb2
import controller_pb2_grpc

from .utils import get_address_family

# The IP address and port of the gRPC server started on the SDN controller
DEFAULT_GRPC_SERVER_IP = '::'
DEFAULT_GRPC_SERVER_PORT = 54321
# Define wheter to use SSL or not
DEFAULT_SECURE = False
# SSL cerificate for server validation
DEFAULT_CERTIFICATE = 'cert_client.pem'

STATUS_UNKNOWN = 0
STATUS_OK = 200
STATUS_BAD_REQUEST = 400
STATUS_UNAUTHORIZED = 401
STATUS_INTERNAL_SERVER_ERROR = 500
STATUS_SERVICE_UNAVAILABLE = 503

# Parser for gRPC errors


def parse_grpc_error(e, ip, port):
    status_code = e.code()
    details = e.details()
    logging.error('gRPC client reported an error: %s, %s'
                  % (status_code, details))
    if grpc.StatusCode.UNAVAILABLE == status_code:
        code = STATUS_SERVICE_UNAVAILABLE
        reason = ('Unable to contact controller - gRPC server is '
                  'unreachable (ip %s, port %s)' % (ip, port))
    elif grpc.StatusCode.UNAUTHENTICATED == status_code:
        code = STATUS_UNAUTHORIZED
        reason = details
    else:
        code = STATUS_INTERNAL_SERVER_ERROR
        reason = details
    # Return an error message
    return code, reason


class STAMPError(Exception):
    """Raised when an error is returned by the Controller.

    Attributes
    ----------
    msg : str
        Human readable string describing the exception.

    """

    def __init__(self, msg=None):
        self.msg = ''
        if msg is not None:
            self.msg = 'An error occurred during the operation: {msg}'.format(
                msg=msg)
        super().__init__(self.msg)


class NorthboundInterface:

    def __init__(self, server_ip=DEFAULT_GRPC_SERVER_IP,
                 server_port=DEFAULT_GRPC_SERVER_PORT,
                 secure=DEFAULT_SECURE, certificate=DEFAULT_CERTIFICATE):
        self.server_ip = server_ip
        self.server_port = server_port
        self.secure = secure
        if secure is True:
            if certificate is None:
                logging.error('Error: "certificate" variable cannot be None '
                              'in secure mode')
                sys.exit(-2)
            self.certificate = certificate
        # Channel
        self.channel = None

    # Build a grpc stub
    def get_grpc_session(self, address, port, secure):
        # Get the address of the server
        addr_family = get_address_family(address)
        if addr_family == AF_INET6:
            server_address = f'ipv6:[{address}]:{port}'
        elif addr_family == AF_INET:
            server_address = f'ipv4:{address}:{port}'
        else:
            logging.error('Invalid address: %s' % address)
            return
        if self.channel is None:
            # If secure we need to establish a channel with the secure endpoint
            if secure:
                # Open the certificate file
                with open(self.certificate, 'rb') as f:
                    certificate = f.read()
                # Then create the SSL credentials and establish the channel
                grpc_client_credentials = grpc.ssl_channel_credentials(
                    certificate)
                self.channel = grpc.secure_channel(server_address,
                                                   grpc_client_credentials)
            else:
                self.channel = grpc.insecure_channel(server_address)
        return (controller_pb2_grpc.STAMPControllerServiceStub(self.channel),
                self.channel)

    def register_stamp_sender(self, node_id, grpc_ip, grpc_port, ip,
                              udp_port=None, node_name=None, interfaces=None,
                              stamp_source_ipv6_address=None,
                              initialize=True):
        # Create request
        request = controller_pb2.RegisterStampSenderRequest()
        request.node_id = node_id
        request.grpc_ip = grpc_ip
        request.grpc_port = grpc_port
        request.ip = ip
        if node_name is not None:
            request.node_name = node_name
        if udp_port is not None:
            request.udp_port = udp_port
        if interfaces is not None:
            request.interfaces = interfaces
        if stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = stamp_source_ipv6_address
        request.initialize = initialize
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.RegisterStampSender(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def register_stamp_reflector(self, node_id, grpc_ip, grpc_port, ip,
                                 udp_port, node_name=None, interfaces=None,
                                 stamp_source_ipv6_address=None,
                                 initialize=True):
        # Create request
        request = controller_pb2.RegisterStampReflectorRequest()
        request.node_id = node_id
        request.grpc_ip = grpc_ip
        request.grpc_port = grpc_port
        request.ip = ip
        request.udp_port = udp_port
        if node_name is not None:
            request.node_name = node_name
        if interfaces is not None:
            request.interfaces = interfaces
        if stamp_source_ipv6_address is not None:
            request.stamp_source_ipv6_address = stamp_source_ipv6_address
        request.initialize = initialize
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.RegisterStampReflector(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def unregister_stamp_node(self, node_id):
        # Create request
        request = controller_pb2.UnregisterStampNodeRequest()
        request.node_id = node_id
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.UnregisterStampNode(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def init_stamp_node(self, node_id):
        # Create request
        request = controller_pb2.InitStampNodeRequest()
        request.node_id = node_id
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.InitStampNode(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def reset_stamp_node(self, node_id):
        # Create request
        request = controller_pb2.ResetStampNodeRequest()
        request.node_id = node_id
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.ResetStampNode(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def create_stamp_session(self, sender_id, reflector_id=None,
                             direct_sidlist=None, return_sidlist=None,
                             interval=None, auth_mode=None,
                             key_chain=None, timestamp_format=None,
                             packet_loss_type=None,
                             delay_measurement_mode=None,
                             session_reflector_mode=None,
                             sender_source_ip=None,
                             reflector_source_ip=None, description=None,
                             duration=0, start_after_creation=False):
        # Create the request
        request = controller_pb2.CreateStampSessionRequest()
        request.sender_id = sender_id
        if reflector_id is not None:
            request.reflector_id = reflector_id
        if direct_sidlist is not None:
            request.direct_sidlist.segments.extend(direct_sidlist)
        if return_sidlist is not None:
            request.return_sidlist.segments.extend(return_sidlist)
        if interval is not None:
            request.interval = interval
        if auth_mode is not None:
            request.stamp_params.auth_mode = auth_mode
        if key_chain is not None:
            request.stamp_params.key_chain = key_chain
        if timestamp_format is not None:
            request.stamp_params.timestamp_format = timestamp_format
        if packet_loss_type is not None:
            request.stamp_params.packet_loss_type = packet_loss_type
        if delay_measurement_mode is not None:
            request.stamp_params.delay_measurement_mode = \
                delay_measurement_mode
        if session_reflector_mode is not None:
            request.stamp_params.session_reflector_mode = \
                session_reflector_mode
        if sender_source_ip is not None:
            request.sender_source_ip = sender_source_ip
        if reflector_source_ip is not None:
            request.reflector_source_ip = reflector_source_ip
        if description is not None:
            request.description = description
        request.duration = duration
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.CreateStampSession(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
            # Eventually, start the STAMP Session after its creation
            if start_after_creation:
                self.start_stamp_session(ssid=response.ssid)
            # Extract and return the SSID
            return response.ssid
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def start_stamp_session(self, ssid):
        # Create the request
        request = controller_pb2.StartStampSessionRequest()
        request.ssid = ssid
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.StartStampSession(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def stop_stamp_session(self, ssid):
        # Create the request
        request = controller_pb2.StopStampSessionRequest()
        request.ssid = ssid
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.StopStampSession(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def destroy_stamp_session(self, ssid):
        # Create the request
        request = controller_pb2.DestroyStampSessionRequest()
        request.ssid = ssid
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            response = grpc_stub.DestroyStampSession(request)
            # Check return code
            if response.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(response.description)
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def get_stamp_results(self, ssid):
        # Create the request
        request = controller_pb2.GetStampResultsRequest()
        request.ssid = ssid
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            reply = grpc_stub.GetStampResults(request)
            # Check return code
            if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(reply.description)

            results = list()
            for result in reply.results:
                measurement_direction = 'unspec'
                if (result.measurement_direction == controller_pb2
                        .MeasurementDirection.MEASUREMENT_DIRECTION_DIRECT):
                    measurement_direction = 'direct'
                elif (result.measurement_direction == controller_pb2
                      .MeasurementDirection.MEASUREMENT_DIRECTION_RETURN):
                    measurement_direction = 'return'
                elif (result.measurement_direction == controller_pb2
                      .MeasurementDirection.MEASUREMENT_DIRECTION_BOTH):
                    measurement_direction = 'both'

                measurement_type = 'unspec'
                if (result.measurement_type == controller_pb2
                        .MeasurementType.MEASUREMENT_TYPE_UNSPECIFIED):
                    measurement_type = 'direct'
                elif (result.measurement_type == controller_pb2
                      .MeasurementType.MEASUREMENT_TYPE_LOSS):
                    measurement_type = 'loss'
                elif (result.measurement_type == controller_pb2
                      .MeasurementType.MEASUREMENT_TYPE_DELAY):
                    measurement_type = 'delay'

                new_result = {
                    'ssid': result.ssid,
                    'direct_sidlist': list(result.direct_sidlist.segments),
                    'return_sidlist': list(result.return_sidlist.segments),
                    'measurement_type': measurement_type,
                    'measurement_direction': measurement_direction,
                    'results': {
                        'direct_path': {
                            'delays': [],
                            'average_delay': -1
                        },
                        'return_path': {
                            'delays': [],
                            'average_delay': -1
                        }
                    }
                }
                new_result['results']['direct_path']['average_delay'] = \
                    result.direct_path_average_delay
                new_result['results']['return_path']['average_delay'] = \
                    result.return_path_average_delay
                for res in result.direct_path_results:
                    new_result['results']['direct_path']['delays'].append({
                        'id': res.id,
                        'value': res.value,
                        'timestamp': res.timestamp
                    })
                for res in result.return_path_results:
                    new_result['results']['return_path']['delays'].append({
                        'id': res.id,
                        'value': res.value,
                        'timestamp': res.timestamp
                    })
                results.append(new_result)
            return results
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])

    def get_stamp_sessions(self, ssid=None):
        # Create the request
        request = controller_pb2.StartStampSessionRequest()
        if ssid is not None:
            request.ssid = ssid
        try:
            # Get the reference of the stub
            grpc_stub, _ = self.get_grpc_session(
                self.server_ip, self.server_port, self.secure)
            # Send the request
            reply = grpc_stub.GetStampSessions(request)
            # Check return code
            if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
                raise STAMPError(reply.description)

            stamp_sessions = list()
            for stamp_session in reply.stamp_sessions:

                session_status = 'unspec'
                if (stamp_session.status == controller_pb2
                        .STAMPSessionStatus.STAMP_SESSION_STATUS_RUNNING):
                    session_status = 'running'
                elif (stamp_session.status == controller_pb2
                      .STAMPSessionStatus.STAMP_SESSION_STATUS_STOPPED):
                    session_status = 'stopped'

                new_session = {
                    'ssid': stamp_session.ssid,
                    'description': stamp_session.description,
                    'status': session_status,
                    'sender_id': stamp_session.sender_id,
                    'sender_name': stamp_session.sender_name,
                    'sender_source_ip': stamp_session.sender_source_ip,
                    'reflector_id': stamp_session.reflector_id,
                    'reflector_name': stamp_session.reflector_name,
                    'reflector_source_ip': stamp_session.reflector_source_ip,
                    'interval': stamp_session.interval,
                    'duration': stamp_session.duration,
                    'auth_mode': stamp_session.stamp_params.auth_mode,
                    'key_chain': stamp_session.stamp_params.key_chain,
                    'timestamp_format':
                    stamp_session.stamp_params.timestamp_format,
                    'packet_loss_type':
                    stamp_session.stamp_params.packet_loss_type,
                    'delay_measurement_mode':
                    stamp_session.stamp_params.delay_measurement_mode,
                    'session_reflector_mode':
                    stamp_session.stamp_params.session_reflector_mode,
                    'direct_sidlist':
                    list(stamp_session.direct_sidlist.segments),
                    'return_sidlist':
                    list(stamp_session.return_sidlist.segments),
                    'average_delay_direct_path':
                    stamp_session.average_delay_direct_path,
                    'average_delay_return_path':
                    stamp_session.average_delay_return_path
                }
                stamp_sessions.append(new_session)
            return stamp_sessions
        except grpc.RpcError as e:
            response = parse_grpc_error(e, self.server_ip, self.server_port)
            raise STAMPError(response[1])
