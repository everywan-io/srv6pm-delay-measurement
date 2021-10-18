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
# Python Library implementing the STAMP protocol [RFC8762].
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""Python Library implementing the STAMP protocol [RFC8762]."""

from .core import (
    Timestamp,
    ParsedSTAMPTestPacket,
    ParsedSTAMPTestReplyPacket,
    STAMPTestPacket,
    STAMPReplyPacket,
    AuthenticationMode,
    TimestampFormat,
    PacketLossType,
    DelayMeasurementMode,
    SessionReflectorMode,
    TimestampFormatFlag,
    SyncFlag,
    get_timestamp_ntp,
    get_timestamp_ptp,
    reassemble_timestamp_ntp,
    reassemble_timestamp_ptp,
    generate_stamp_test_packet,
    generate_stamp_reply_packet,
    parse_stamp_test_packet,
    parse_stamp_reply_packet,
    send_stamp_packet
)

__all__ = [
    'Timestamp',
    'ParsedSTAMPTestPacket',
    'ParsedSTAMPTestReplyPacket',
    'STAMPTestPacket',
    'STAMPReplyPacket',
    'AuthenticationMode',
    'TimestampFormat',
    'PacketLossType',
    'DelayMeasurementMode',
    'SessionReflectorMode',
    'TimestampFormatFlag',
    'SyncFlag',
    'get_timestamp_ntp',
    'get_timestamp_ptp',
    'reassemble_timestamp_ntp',
    'reassemble_timestamp_ptp',
    'generate_stamp_test_packet',
    'generate_stamp_reply_packet',
    'parse_stamp_test_packet',
    'parse_stamp_reply_packet',
    'send_stamp_packet'
]
