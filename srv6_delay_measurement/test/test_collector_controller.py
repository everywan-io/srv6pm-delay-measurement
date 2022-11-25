import sys

sys.path.append('/proj/superfluidity-PG0/carmine/srv6pm-delay-measurement/srv6_delay_measurement/commons/protos/srv6pm/gen_py')

import common_pb2
import stamp_sender_pb2, stamp_sender_pb2_grpc

import grpc
from socket import AF_INET, AF_INET6

#sender_ip='c220g1-030627.wisc.cloudlab.us'
sender_ip = '128.105.145.200'
sender_port = 12345

ssid=0
stamp_source_ipv6_address='12:2::2'
interval=3
auth_mode=0
key_chain=None
timestamp_format=0
packet_loss_type=0
delay_measurement_mode=0
reflector_udp_port=862
segments=['f2::', 'f1::']


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
    # Get the address of the server
    addr_family = AF_INET
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


def create_stamp_sender_session(ssid=ssid, 
                                 sidlist=None, interval=interval, auth_mode=auth_mode,
                                 key_chain=key_chain, timestamp_format=timestamp_format,
                                 packet_loss_type=packet_loss_type,
                                 delay_measurement_mode=delay_measurement_mode,
                                 source_ip=stamp_source_ipv6_address):
    if sidlist is None:
        sidlist = []

    # Create a request message
    request = stamp_sender_pb2.CreateStampSenderSessionRequest()

    # Fill the request message
    request.ssid = ssid
    request.sidlist.segments.extend(sidlist)
    request.interval = interval
    request.stamp_params.reflector_ip = '::'
    request.stamp_params.reflector_udp_port = reflector_udp_port

    # Fill in optional parameters
    if source_ip is not None:
        request.stamp_source_ipv6_address = source_ip
    if auth_mode is not None:
        request.stamp_params.auth_mode = auth_mode
    if key_chain is not None:
        request.stamp_params.key_chain = key_chain
    if timestamp_format is not None:
        request.stamp_params.timestamp_format = timestamp_format
    if packet_loss_type is not None:
        request.stamp_params.packet_loss_type = packet_loss_type
    if delay_measurement_mode is not None:
        request.stamp_params.delay_measurement_mode = delay_measurement_mode

    # Invoke the RPC
    _, grpc_stub_sender = get_grpc_channel_sender(sender_ip, sender_port)
    reply = grpc_stub_sender.CreateStampSession(request)
    if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
        # Raise an exception
        raise Exception('Cannot create STAMP Session')

    # Return the reply
    return reply
    

def start_stamp_session(ssid=ssid):
    # Start STAMP Session on the Sender
    request = stamp_sender_pb2.StartStampSenderSessionRequest()
    request.ssid = ssid
    _, grpc_stub_sender = get_grpc_channel_sender(sender_ip, sender_port)
    reply = grpc_stub_sender.StartStampSession(request)
    if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
        raise Exception('Cannot start STAMP Session on Sender')
    

def stop_stamp_session(ssid=ssid):
    # Start STAMP Session on the Sender
    request = stamp_sender_pb2.StopStampSenderSessionRequest()
    request.ssid = ssid
    _, grpc_stub_sender = get_grpc_channel_sender(sender_ip, sender_port)
    reply = grpc_stub_sender.StopStampSession(request)
    if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
        raise Exception('Cannot stop STAMP Session on Sender')
    

def destroy_stamp_session(ssid=ssid):
    # Start STAMP Session on the Sender
    request = stamp_sender_pb2.DestroyStampSenderSessionRequest()
    request.ssid = ssid
    _, grpc_stub_sender = get_grpc_channel_sender(sender_ip, sender_port)
    reply = grpc_stub_sender.DestroyStampSession(request)
    if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
        raise Exception('Cannot destroy STAMP Session on Sender')
    

def fetch_stamp_results(ssid=ssid):
    request = stamp_sender_pb2.GetStampSessionResultsRequest()
    request.ssid = ssid
    _, grpc_stub_sender = get_grpc_channel_sender(sender_ip, sender_port)
    reply = (grpc_stub_sender.GetStampSessionResults(request))
    if reply.status != common_pb2.StatusCode.STATUS_CODE_SUCCESS:
        raise Exception('Cannot fetch STAMP Session results')

    # Count results
    return len(reply.results)


if __name__ == '__main__':
    create_stamp_sender_session()
    start_stamp_session()
    stop_stamp_session()
    print('collected results: ', fetch_stamp_results())
    destroy_stamp_session()

