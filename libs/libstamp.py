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
# Python Library implementing the STAMP protocol [RFC8762]
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""
Python Library implementing the STAMP protocol [RFC8762].
"""


import enum
import logging

from collections import namedtuple
from datetime import datetime

from scapy.all import send
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    IntField,
    ShortField)
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting
from scapy.packet import Packet


Timestamp = namedtuple('Timestamp', 'seconds fraction')

StampTestPacket = namedtuple('StampTestPacket',
                             'src_ip dst_ip src_udp_port dst_udp_port '
                             'sequence_number ssid timestamp '
                             'timestamp_seconds timestamp_fraction s_flag '
                             'z_flag scale multiplier ttl')

StampTestReplyPacket = namedtuple('StampTestReplyPacket',
                                  'sequence_number ssid timestamp '
                                  'timestamp_seconds timestamp_fraction '
                                  's_flag z_flag scale multiplier '
                                  'receive_timestamp '
                                  'receive_timestamp_seconds '
                                  'receive_timestamp_fraction '
                                  'sender_timestamp sender_timestamp_seconds '
                                  'sender_timestamp_fraction s_flag_sender '
                                  'z_flag_sender scale_sender '
                                  'multiplier_sender ttl_sender')


# Constants to convert Unix timestamps to NTP version 4 64-bit
# binary format [RFC5905]
# Unix Time and NTP differ by 70 years in seconds and 17 leap years
# Therefore, the offset is computed as (70*365 + 17)*86400 = 2208988800
# Time Difference: 1-JAN-1900 to 1-JAN-1970
UNIX_TO_NTP_TIMESTAMP_OFFSET = int(2208988800)  # 1-JAN-1900 to 1-JAN-1970
_32_BIT_MASK = int(0xFFFFFFFF)     # To calculate 32bit fraction of the second


class STAMPTestPacket(Packet):       # TODO Rivedere nomi classi e nomi campi
    name = "TWAMPPacketSender"
    fields_desc = [IntField("SequenceNumber", 0),
                   BitField("FirstPartTimestamp", 0, 32),
                   BitField("SecondPartTimestamp", 0, 32),
                   BitEnumField("S", 0, 1, {0: " no external synchronization",
                                            1: "external synchronization"}),
                   BitField("Z", 0, 1),
                   BitField("Scale", 0, 6),
                   BitField("Multiplier", 1, 8),
                   ShortField("ssid", 0)]  # TODO manca il padding


class STAMPReplyPacket(Packet):       # TODO Rivedere nomi classi e nomi campi
    name = "TWAMPPacketReflector"
    fields_desc = [IntField("SequenceNumber", 0),
                   BitField("FirstPartTimestamp", 0, 32),
                   BitField("SecondPartTimestamp", 0, 32),
                   BitEnumField("S", 0, 1, {0: " no external synchronization",
                                            1: "external synchronization"}),
                   BitField("Z", 0, 1),
                   BitField("Scale", 0, 6),
                   BitField("Multiplier", 1, 8),
                   ShortField("ssid", 0),
                   BitField("FirstPartTimestampReceiver", 0, 32),
                   BitField("SecondPartTimestampReceiver", 0, 32),
                   IntField("SequenceNumberSender", 0),
                   BitField("FirstPartTimestampSender", 0, 32),
                   BitField("SecondPartTimestampSender", 0, 32),
                   BitEnumField("SSender", 0, 1, {
                       0: " no external synchronization",
                       1: "external synchronization"}),
                   BitField("ZSender", 0, 1),
                   BitField("ScaleSender", 0, 6),
                   BitField("MultiplierSender", 1, 8),
                   BitField("MBZ", 0, 16),
                   ByteField("SenderTTL", 255)]  # TODO manca il padding


# Enum used by STAMP Sender and STAMP Reflector

class AuthenticationMode(enum.Enum):
    """Authentication mode."""

    # Authentication mode not specified
    AUTHENTICATION_MODE_UNSPECIFIED = 'unspec'

    # STAMP in unauthenticated mode
    AUTHENTICATION_MODE_UNAUTHENTICATED = 'unauth'

    # STAMP in authenticated mode (using HMAC SHA 256 algorithm)
    AUTHENTICATION_MODE_HMAC_SHA_256 = 'hmac-sha-256'


class TimestampFormat(enum.Enum):
    """Format used for Timestamp."""

    # Timestamp format not specified
    TIMESTAMP_FORMAT_UNSPECIFIED = 'unspec'

    # IEEE 1588v2 Precision Time Protocol (PTP) truncated 64-bit timestamp
    # format [IEEE.1588.2008]
    TIMESTAMP_FORMAT_PTPv2 = 'ptp'

    # Network Time Protocol (NTP) version 4 64-bit timestamp format [RFC5905]
    TIMESTAMP_FORMAT_NTP = 'ntp'


class PacketLossType(enum.Enum):
    """Type of Packet Loss Measurement."""

    # Packet loss type not specified
    PACKET_LOSS_TYPE_UNSPECIFIED = 'unspec'

    # Round trip Packet Loss
    PACKET_LOSS_TYPE_ROUND_TRIP = 'round-trip'

    # Near End Packet Loss
    PACKET_LOSS_TYPE_NEAR_END = 'near-end'

    # Far End Packet Loss
    PACKET_LOSS_TYPE_FAR_END = 'far-end'


class DelayMeasurementMode(enum.Enum):
    """Delay Measurement Mode."""

    # Delay Measurement Mode unspecified
    DELAY_MEASUREMENT_MODE_UNSPECIFIED = 'unspec'

    # One-Way Measurement Mode
    DELAY_MEASUREMENT_MODE_ONE_WAY = 'one-way'

    # Two-Way Measurement Mode
    DELAY_MEASUREMENT_MODE_TWO_WAY = 'two-way'

    # Loopback Measurement Mode
    DELAY_MEASUREMENT_MODE_LOOPBACK = 'loopback'


class SessionReflectorMode(enum.Enum):
    """Reflector mode."""

    # Reflector mode unspecified
    SESSION_REFLECTOR_MODE_UNSPECIFIED = 'unspec'

    # Reflector working in Stateless mode
    SESSION_REFLECTOR_MODE_STATELESS = 'stateless'

    # Reflector working in Stateful mode
    SESSION_REFLECTOR_MODE_STATEFUL = 'stateful'


class TimestampFormatFlag(enum.Enum):
    """Format used for Timestamp."""

    # Network Time Protocol (NTP) version 4 64-bit timestamp format [RFC5905]
    NTP_v4 = 0

    # IEEE 1588v2 Precision Time Protocol (PTP) truncated 64-bit timestamp
    # format [IEEE.1588.2008]
    PTP_V2 = 1


class SyncFlag(enum.Enum):
    """Synchronization flag contained in the Error Estimate field."""

    # No external source is used for clock synchronization
    NO_EXT_SYNC = 0

    # The party generating the timestamp has a clock that is synchronized to
    # UTC using an external source (e.g. GPS hardware)
    EXT_SYNC = 1


def get_timestamp_ntp():
    """
    Return the current timestamp expressed in Network Time Protocol (NTP)
    version 4 64-bit timestamp format [RFC5905].

    Returns
    -------
    timestamp_seconds : int
        Seconds expressed as 32-bit unsigned int (spanning 136 years).
    timestamp_fraction : int
        Fraction of second expressed as 32-bit unsigned int (resolving 232
         picoseconds).
    """

    logging.debug('NTP Timestamp requested')

    # Get Unix Timestamp
    #
    # datetime uses an epoch of January 1, 1970 00:00h (Unix Time)
    # NTP uses an epoch of January 1, 1900 00:00h
    # To get the NTP timestamp, we need to add an offset to the datetime
    # timestamp (70 years + 17 leap years)
    timestamp = \
        datetime.timestamp(datetime.now()) + UNIX_TO_NTP_TIMESTAMP_OFFSET

    # Split timestamp in seconds and fraction of seconds
    #
    # Seconds expressed as 32-bit unsigned int
    timestamp_seconds = int(timestamp)
    # 32-bit fraction of the second
    timestamp_fraction = int((timestamp - int(timestamp)) * _32_BIT_MASK)

    logging.debug('NTP Timestamp: {sec} seconds, {fraction} fractional seconds'
                  .format(sec=timestamp_seconds, fraction=timestamp_fraction))

    # Return the seconds expressed as 32-bit unsigned int and the Fraction of
    # second expressed as 32-bit unsigned int
    return Timestamp(seconds=timestamp_seconds, fraction=timestamp_fraction)


def get_timestamp_ptp():
    """
    Return the current timestamp expressed in IEEE 1588v2 Precision Time
    Protocol (PTP) truncated 64-bit timestamp format [IEEE.1588.2008].

    Returns
    -------
    timestamp_seconds : int
        Seconds since the epoch expressed as 32-bit unsigned int (spanning 136
         years). The PTP [IEEE1588] epoch is 1 January 1970 00:00:00 TAI.
    timestamp_nanoseconds : int
        Fraction of second since the epoch expressed as 32-bit unsigned int
         (resolving 232 picoseconds). The PTP [IEEE1588] epoch is 1 January
         1970 00:00:00 TAI.
    """

    logging.debug('PTP Timestamp requested')

    raise NotImplementedError


def reassemble_timestamp_ntp(timestamp_seconds, timestamp_fraction):
    """
    Take seconds and fractional seconds and return the NTPv4 timestamp.

    Parameters
    ----------
    timestamp_seconds : int
        Seconds expressed as 32-bit unsigned int (spanning 136 years).
    timestamp_fraction : int
        Fraction of second expressed as 32-bit unsigned int (resolving 232
         picoseconds).

    Returns
    -------
    timestamp : float
        The reassembled NTPv4 Timestamp.
    """

    timestamp = timestamp_seconds + \
        float('0.{fraction}'.format(fraction=timestamp_fraction))

    logging.debug('Reassembling NTP Timestamp, seconds: {seconds}, '
                  'fraction: {fraction}, reassembled timestamp: {timestamp}'
                  .format(
                      seconds=timestamp_seconds,
                      fraction=timestamp_fraction,
                      timestamp=timestamp))

    return timestamp


def reassemble_timestamp_ptp(timestamp_seconds, timestamp_fraction):
    """
    Take seconds and fractional seconds and return the PTPv2 timestamp.

    Parameters
    ----------
    timestamp_seconds : int
        Seconds since the epoch expressed as 32-bit unsigned int (spanning 136
         years). The PTP [IEEE1588] epoch is 1 January 1970 00:00:00 TAI.
    timestamp_fraction : int
        Fraction of second since the epoch expressed as 32-bit unsigned int
         (resolving 232 picoseconds). The PTP [IEEE1588] epoch is 1 January
         1970 00:00:00 TAI.

    Returns
    -------
    timestamp : float
        The reassembled PTPv2 Timestamp.
    """

    raise NotImplementedError


def generate_stamp_test_packet(
        src_ip, dst_ip, src_udp_port, dst_udp_port,
        sidlist, ssid, sequence_number,
        timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
        ext_source_sync=False, scale=0, multiplier=1):
    """
    Generate a STAMP Test packet.

    Parameters
    ----------
    src_ip : str
        Source IP address of the STAMP Test packet.
    dst_ip : str
        Destination IP address of the STAMP Test packet.
    src_udp_port : int
        Source UDP port of the STAMP Test packet.
    dst_udp_port : int
        Destination UDP port of the STAMP Test packet.
    sidlist : list
        Segment List to be used for the STAMP packet.
    ssid : int
        STAMP Session Sender Identifier.
    sequence_number : int
        Sequence Number of the STAMP Test packet.
    timestamp_format : str, optional
        Format of the timestamp to be used for the STAMP packet. Two timestamp
         formats are supported by STAMP: "ntp" and "ptp" (default "ntp").
    ext_source_sync : bool, optional
        Whether an external source is used to synchronize the Sender and
         Reflector clocks (default False).
    scale: int, optional
        Scale field of the Error Estimate field (default 0).
    multiplier: int, optional
        Multiplier field of the Error Estimate field (default 1).

    Returns
    -------
    packet : scapy.packet.Packet
        The generated STAMP Test.
    """

    # Get the timestamp depending on the timestamp format
    if timestamp_format == TimestampFormat.TIMESTAMP_FORMAT_NTP.value:
        timestamp_format_flag = TimestampFormatFlag.NTP_v4.value
        timestamp = get_timestamp_ntp()
    elif timestamp_format == TimestampFormat.TIMESTAMP_FORMAT_PTPv2.value:
        timestamp_format_flag = TimestampFormatFlag.PTP_V2.value
        timestamp = get_timestamp_ptp()

    # Translate external source sync
    if ext_source_sync:
        sync_flag = SyncFlag.EXT_SYNC.value
    else:
        sync_flag = SyncFlag.NO_EXT_SYNC.value

    # Build IPv6 header
    ipv6_header = IPv6()
    ipv6_header.src = src_ip
    ipv6_header.dst = sidlist[0]

    # Build SRv6 header
    srv6_header = IPv6ExtHdrSegmentRouting()
    srv6_header.addresses = sidlist[::-1]
    srv6_header.segleft = len(sidlist) - 1
    srv6_header.lastentry = len(sidlist) - 1

    # Build UDP header
    udp_header = UDP()
    udp_header.dport = dst_udp_port
    udp_header.sport = src_udp_port

    # Build payload (i.e. the STAMP packet)
    stamp_packet = STAMPTestPacket(  # TODO conflitto nomi con namedtuple
        SequenceNumber=sequence_number,
        FirstPartTimestamp=timestamp.seconds,
        SecondPartTimestamp=timestamp.fraction,
        S=sync_flag,
        Z=timestamp_format_flag,
        Scale=scale,
        Multiplier=multiplier
    )

    # Assemble the whole packet
    packet = ipv6_header / srv6_header / udp_header / stamp_packet

    # Return the packet
    return packet


def generate_stamp_reply_packet(
        stamp_test_packet, src_ip, dst_ip,
        src_udp_port, dst_udp_port, sidlist, ssid, sequence_number=None,
        timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
        ext_source_sync=False, scale=0, multiplier=1):
    """
    Generate a STAMP Test Reply packet.

    Parameters
    ----------
    stamp_test_packet : scapy.packet.Packet
        The STAMP Test packet for which this packet is the reply. This is used
         to fill some fields with the data contained in the STAMP Test packet,
         as described by RFC 8762.
    src_ip : str
        Source IP address of the STAMP Test Reply packet.
    dst_ip : str
        Destination IP address of the STAMP Test Reply packet.
    src_udp_port : int
        Source UDP port of the STAMP Test Reply packet.
    dst_udp_port : int
        Destination UDP port of the STAMP Test Reply packet.
    sidlist : list
        Segment List to be used for the STAMP packet.
    ssid : int
        STAMP Session Sender Identifier.
    sequence_number : int, optional
        Sequence Number to use in the STAMP Test Reply packet. If None, the
         Sequence Number field is the same of the Sequence Number of the STAMP
         Test Packet received. This is useful to implement STAMP Reflector
         Stateless Mode (default None).
    timestamp_format : str, optional
        Format of the timestamp to be used for the STAMP Test Reply packet.
         Two timestamp formats are supported by STAMP: "ntp" and "ptp"
         (default "ntp").
    ext_source_sync : bool, optional
        Whether an external source is used to synchronize the Sender and
         Reflector clocks (default False).
    scale: int, optional
        Scale field of the Error Estimate field (default 0).
    multiplier: int, optional
        Multiplier field of the Error Estimate field (default 1).

    Returns
    -------
    packet : scapy.packet.Packet
        The generated STAMP Test.
    """

    # Parse the STAMP Test packet received from the STAMP Session-Sender
    parsed_stamp_test_packet = parse_stamp_test_packet(stamp_test_packet)

    # Get the timestamp depending on the timestamp format
    if timestamp_format == TimestampFormat.TIMESTAMP_FORMAT_NTP.value:
        timestamp_format_flag = TimestampFormatFlag.NTP_v4.value
        timestamp = get_timestamp_ntp()
    elif timestamp_format == TimestampFormat.TIMESTAMP_FORMAT_PTPv2.value:
        timestamp_format_flag = TimestampFormatFlag.PTP_V2.value
        timestamp = get_timestamp_ptp()

    # Translate external source sync
    if ext_source_sync:
        sync_flag = SyncFlag.EXT_SYNC.value
    else:
        sync_flag = SyncFlag.NO_EXT_SYNC.value

    # If the Sender sequence number argument has not been provided, we extract
    # the sequence number from the STAMP Test packet received from the Sender
    # and we use it in as sequence number in the STAMP Test Reply packet.
    # If a Sequence Number has been passed as argument to this function, it
    # will be used as Sequence Number in the STAMP Reply packet.
    #
    # This approach is useful to implement the two Session Reflector Modes
    # described in RFC8762:
    #     * Stateless Mode: the STAMP Test Reply uses the same Sequence Number
    #       as the STAMP Test packet
    #     * Stateful Mode: the STAMP Reflector maintains its own Sequence
    #       Number as part of its STAMP Session state
    if sequence_number is None:
        sequence_number = parsed_stamp_test_packet.sequence_number

    # Build IPv6 header
    ipv6_header = IPv6()
    ipv6_header.src = src_ip
    ipv6_header.dst = sidlist[0]

    # Build SRv6 header
    srv6_header = IPv6ExtHdrSegmentRouting()
    srv6_header.addresses = sidlist[::-1]
    srv6_header.segleft = len(sidlist) - 1
    srv6_header.lastentry = len(sidlist) - 1

    # Build UDP header
    udp_header = UDP()
    udp_header.dport = dst_udp_port
    udp_header.sport = src_udp_port

    # Build payload (i.e. the STAMP packet)
    stamp_packet = STAMPReplyPacket(
        SequenceNumber=sequence_number,
        FirstPartTimestamp=timestamp.seconds,
        SecondPartTimestamp=timestamp.fraction,
        S=sync_flag,
        Z=timestamp_format_flag,
        Scale=scale,
        Multiplier=multiplier,
        MBZ=0,
        FirstPartTimestampReceiver=timestamp.seconds,
        SecondPartTimestampReceiver=timestamp.fraction,
        SequenceNumberSender=parsed_stamp_test_packet.sequence_number,
        FirstPartTimestampSender=parsed_stamp_test_packet.timestamp_seconds,
        SecondPartTimestampSender=parsed_stamp_test_packet.timestamp_fraction,
        SSender=parsed_stamp_test_packet.s_flag,
        ZSender=parsed_stamp_test_packet.z_flag,
        ScaleSender=parsed_stamp_test_packet.scale,
        MultiplierSender=parsed_stamp_test_packet.multiplier,
        SenderTTL=parsed_stamp_test_packet.ttl
    )

    # Assemble the whole packet
    packet = ipv6_header / srv6_header / udp_header / stamp_packet

    # Return the packet
    return packet


def parse_stamp_test_packet(packet):
    """
    Parse a STAMP Test packet and extract relevant fields.

    Parameters
    ----------
    packet : scapy.packet.Packet
        The STAMP Test packet to parse.

    Returns
    -------
    parsed_packet : libstamp.StampTestPacket
        The parsed STAMP Test packet.
    """

    # Parse IPv6 header
    dst_ip = packet[IPv6].dst
    src_ip = packet[IPv6].src
    ttl = packet[IPv6].hlim

    # Parse the UDP header
    dst_udp_port = packet[UDP].dport
    src_udp_port = packet[UDP].sport

    # Parse the payload (i.e. the STAMP Test packet)
    packet[UDP].decode_payload_as(STAMPTestPacket)
    sequence_number = packet[UDP].SequenceNumber
    ssid = packet[UDP].ssid
    timestamp_seconds = packet[UDP].FirstPartTimestamp
    timestamp_fraction = packet[UDP].SecondPartTimestamp
    # TODO dipende dal formato del timestamp
    timestamp = reassemble_timestamp_ntp(timestamp_seconds, timestamp_fraction)
    s_flag = packet[UDP].S
    z_flag = packet[UDP].Z
    scale = packet[UDP].Scale
    multiplier = packet[UDP].Multiplier

    # Aggregate parsed information in a namedtuple
    parsed_packet = StampTestPacket(src_ip=src_ip, dst_ip=dst_ip,
                                    src_udp_port=src_udp_port,
                                    dst_udp_port=dst_udp_port,
                                    ssid=ssid,
                                    sequence_number=sequence_number,
                                    timestamp_seconds=timestamp_seconds,
                                    timestamp_fraction=timestamp_fraction,
                                    timestamp=timestamp, s_flag=s_flag,
                                    z_flag=z_flag, scale=scale,
                                    multiplier=multiplier, ttl=ttl)

    # Return the parsed STAMP Test packet
    return parsed_packet


def parse_stamp_reply_packet(packet):
    """
    Parse a STAMP Test Reply packet and extract relevant fields.

    Parameters
    ----------
    packet : scapy.packet.Packet
        The STAMP Test Reply packet to parse.

    Returns
    -------
    parsed_packet : libstamp.StampTestReplyPacket
        The parsed STAMP Test Reply packet.
    """

    # Parse the payload (i.e. the STAMP Test Reply packet) and extract the
    # three timestamps from the packet
    packet[UDP].decode_payload_as(STAMPReplyPacket)
    sequence_number = packet[UDP].SequenceNumber
    ssid = packet[UDP].ssid
    timestamp_seconds = packet[UDP].FirstPartTimestamp
    timestamp_fraction = packet[UDP].SecondPartTimestamp
    timestamp = reassemble_timestamp_ntp(
        timestamp_seconds, timestamp_fraction)  # TODO dipende dal z flag
    s_flag = packet[UDP].S
    z_flag = packet[UDP].Z
    scale = packet[UDP].Scale
    multiplier = packet[UDP].Multiplier
    receive_timestamp_seconds = packet[UDP].FirstPartTimestampReceiver
    receive_timestamp_fraction = packet[UDP].SecondPartTimestampReceiver
    receive_timestamp = reassemble_timestamp_ntp(
        receive_timestamp_seconds, receive_timestamp_fraction)   # TODO dipende dal z flag
    sender_timestamp_seconds = packet[UDP].FirstPartTimestampSender
    sender_timestamp_fraction = packet[UDP].SecondPartTimestampSender
    sender_timestamp = reassemble_timestamp_ntp(
        sender_timestamp_seconds, sender_timestamp_fraction)   # TODO dipende dal z flag
    s_flag_sender = packet[UDP].SSender
    z_flag_sender = packet[UDP].ZSender
    scale_sender = packet[UDP].ScaleSender
    multiplier_sender = packet[UDP].MultiplierSender
    ttl_sender = packet[UDP].SenderTTL

    # Aggregate parsed information in a namedtuple
    parsed_packet = StampTestReplyPacket(
        sequence_number=sequence_number, ssid=ssid, timestamp=timestamp,
        timestamp_seconds=timestamp_seconds,
        timestamp_fraction=timestamp_fraction, s_flag=s_flag, z_flag=z_flag,
        scale=scale, multiplier=multiplier,
        receive_timestamp=receive_timestamp,
        sender_timestamp=sender_timestamp,
        receive_timestamp_seconds=receive_timestamp_seconds,
        receive_timestamp_fraction=receive_timestamp_fraction,
        sender_timestamp_seconds=sender_timestamp_seconds,
        sender_timestamp_fraction=sender_timestamp_fraction,
        s_flag_sender=s_flag_sender, z_flag_sender=z_flag_sender,
        scale_sender=scale_sender, multiplier_sender=multiplier_sender,
        ttl_sender=ttl_sender)

    # Return the parsed STAMP Test Reply packet
    return parsed_packet


def send_stamp_packet(packet, socket=None):
    """
    Send a STAMP packet (Test packet or Reply packet).

    Parameters
    ----------
    packet : scapy.packet.Packet
        The STAMP packet to be sent
    socket : scapy.arch.linux.SuperSocket, optional
        The socket on which the STAMP packet should be sent. If socket is
         None, this function will open a new socket, send the packets and close
         the socket (default None).

    Returns
    -------
    None.
    """

    # If a socket has been provided, we use the provided socket
    if socket is not None:
        logging.debug('Sending packet %s, reusing opened socket', packet)
        socket.send(packet)
    else:
        # Otherwise, we use the send() function, which will open a new socket
        # and close it after sending the packet
        logging.debug('Sending packet %s, opening a new socket', packet)
        send(packet, verbose=0)

    logging.debug('Packet sent')


# TODO ottimizzare pacchetto

# TODO aggiungere srv6 e ssid al pkt

# TODO inline o encap?
