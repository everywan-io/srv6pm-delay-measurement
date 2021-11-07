from time import sleep

from reflector import STAMPSessionReflector

from libs.libstamp import (
    AuthenticationMode,
    TimestampFormat,
    SessionReflectorMode
)

# Create a STAMP Session Reflector
reflector = STAMPSessionReflector()

reflector.init(
    reflector_udp_port=50052,
    interfaces=['enp6s0f0'],
    stamp_source_ipv6_address=None
)

reflector.create_stamp_session(
    ssid=0,
    stamp_source_ipv6_address='fcf0:0:2:1::2',
    auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
    key_chain=None,
    timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
    session_reflector_mode=SessionReflectorMode
    .SESSION_REFLECTOR_MODE_STATELESS.value,
    reflector_udp_port=50052,
    segments=['fcf0:0:2:1::1', 'fcff:1::100']
)

reflector.start_stamp_session(ssid=0)

try:
    while True:
        sleep(10)
except KeyboardInterrupt:
    print('CTRL+C catched. Graceful stopping...')

    reflector.stop_stamp_session(ssid=0)
    reflector.destroy_stamp_session(ssid=0)
    reflector.reset()
