from time import sleep
from concurrent import futures
import sys

sys.path.append('/proj/superfluidity-PG0/carmine/srv6pm-delay-measurement/srv6_delay_measurement/commons/protos/srv6pm/gen_py')

import stamp_sender_pb2_grpc

import grpc

from srv6_delay_measurement.sender import STAMPSessionSender, STAMPSessionSenderServicer

from srv6_delay_measurement.libs.libstamp import (
    AuthenticationMode,
    TimestampFormat,
    DelayMeasurementMode,
    PacketLossType
)

# Create a STAMP Session Sender
sender = STAMPSessionSender()

server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
stamp_sender_pb2_grpc.add_STAMPSessionSenderServiceServicer_to_server(
        STAMPSessionSenderServicer(sender), server)

grpc_port = 12345

# If gRPC IP address is not provided, listen on any IP address
# Listen on any IPv4 address
server.add_insecure_port('0.0.0.0:{port}'.format(port=grpc_port))
# Listen on any IPv6 address
server.add_insecure_port('[::]:{port}'.format(port=grpc_port))

# Start the server and block until it is terminated
#logger.info('Listening gRPC, port %d', grpc_port)
server.start()
#server.wait_for_termination()


sender.init(
    sender_udp_port=42069,
    interfaces=['enp6s0f0'],
    stamp_source_ipv6_address=None
)

sender.create_stamp_session(
    reflector_ip='2001::1',
    ssid=0,
    stamp_source_ipv6_address='12:2::2',
    interval=3,
    auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
    key_chain=None,
    timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
    packet_loss_type=PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP,
    delay_measurement_mode=DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY,
    reflector_udp_port=862,
    segments=['f2::', 'f1::'],
    #only_collector=True
)

sender.start_stamp_session(ssid=0, only_collector=True)

try:
    print('sleep 10')
    while True:
        sleep(10)
except KeyboardInterrupt:
    print('CTRL+C catched. Graceful stopping...')

    session = stamp_sessions.get(0, None)
    if session is not None:
        if session.is_running:
            sender.stop_stamp_session(ssid=0)
        sender.destroy_stamp_session(ssid=0)

    sender.reset()
