from time import sleep

from srv6_delay_measurement.sender import STAMPSessionSender

from srv6_delay_measurement.libs.libstamp import (
    AuthenticationMode,
    TimestampFormat,
    DelayMeasurementMode,
    PacketLossType
)

# Create a STAMP Session Sender
sender = STAMPSessionSender()

sender.init(
    sender_udp_port=42069,
    interfaces=['enp6s0f0'],
    stamp_source_ipv6_address=None
)

sender.create_stamp_session(
    ssid=0,
    stamp_source_ipv6_address='12:2::2',
    interval=3,
    auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
    key_chain=None,
    timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
    packet_loss_type=PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP,
    delay_measurement_mode=DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY,
    reflector_udp_port=862,
    segments=['f2::', 'f1::']
)

sender.start_stamp_session(ssid=0)

try:
    print('sleep 10')
    while True:
        sleep(10)
except KeyboardInterrupt:
    print('CTRL+C catched. Graceful stopping...')

    sender.stop_stamp_session(ssid=0)
    sender.destroy_stamp_session(ssid=0)
    sender.reset()
