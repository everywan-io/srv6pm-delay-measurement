from time import sleep

from srv6_delay_measurement.reflector import STAMPSessionReflector

from srv6_delay_measurement.libs.libstamp import (
    AuthenticationMode,
    TimestampFormat,
    SessionReflectorMode
)

# PROFILE
#import cProfile
#import re
#cProfile.run('re.compile("build_stamp_test_packets_sniffer")')
# ###

# Create a STAMP Session Reflector
reflector = STAMPSessionReflector()

reflector.init(
    reflector_udp_port=862,
    interfaces=['enp6s0f0'],
    stamp_source_ipv6_address=None
)

reflector.create_stamp_session(
    ssid=0,
    stamp_source_ipv6_address='12:2::2',
    auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
    key_chain=None,
    timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
    session_reflector_mode=SessionReflectorMode
    .SESSION_REFLECTOR_MODE_STATELESS.value,
    reflector_udp_port=862,
    segments=['f2::', 'f1::']
)

reflector.start_stamp_session(ssid=0)

try:
    print('sleep 10')
    while True:
        sleep(10)
except KeyboardInterrupt:
    print('CTRL+C catched. Graceful stopping...')

    reflector.stop_stamp_session(ssid=0)
    reflector.destroy_stamp_session(ssid=0)
    reflector.reset()
