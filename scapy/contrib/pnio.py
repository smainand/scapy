# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2016 Gauthier Sebaux

# scapy.contrib.description = ProfinetIO base layer
# scapy.contrib.status = loads

"""
A simple and non exhaustive Profinet IO layer for scapy
"""

# Scapy imports
import copy
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from scapy.fields import (
    XShortEnumField, BitEnumField, XBitField,
    BitField, StrField, PacketListField,
    StrFixedLenField, ShortField,
    FlagsField, ByteField, XIntField, X3BytesField
)
from scapy.error import Scapy_Exception
from scapy.config import conf

# Some constants
PNIO_FRAME_IDS = {
    0x0020: "PTCP-RTSyncPDU-followup",
    0x0080: "PTCP-RTSyncPDU",
    0xFC01: "Alarm High",
    0xFE01: "Alarm Low",
    0xFEFC: "DCP-Hello-Req",
    0xFEFD: "DCP-Get-Set",
    0xFEFE: "DCP-Identify-ReqPDU",
    0xFEFF: "DCP-Identify-ResPDU",
    0xFF00: "PTCP-AnnouncePDU",
    0xFF20: "PTCP-FollowUpPDU",
    0xFF40: "PTCP-DelayReqPDU",
    0xFF41: "PTCP-DelayResPDU-followup",
    0xFF42: "PTCP-DelayFuResPDU",
    0xFF43: "PTCP-DelayResPDU",
}


def i2s_frameid(x):
    if x in PNIO_FRAME_IDS:
        return PNIO_FRAME_IDS[x]
    elif 0x0100 <= x < 0x1000:
        return "RT_CLASS_3 (%4x)" % x
    elif 0x8000 <= x < 0xC000:
        return "RT_CLASS_1 (%4x)" % x
    elif 0xC000 <= x < 0xFC00:
        return "RT_CLASS_UDP (%4x)" % x
    elif 0xFF80 <= x < 0xFF90:
        return "FragmentationFrameID (%4x)" % x
    return x


def s2i_frameid(x):
    try:
        idx = PNIO_FRAME_IDS.values().index(x)
        return PNIO_FRAME_IDS.keys()[idx]
    except ValueError:
        pass
    if x == "RT_CLASS_3":
        return 0x0100
    elif x == "RT_CLASS_1":
        return 0x8000
    elif x == "RT_CLASS_UDP":
        return 0xC000
    elif x == "FragmentationFrameID":
        return 0xFF80
    return x


#################
#  PROFINET IO  #
#################

class ProfinetIO(Packet):
    """Basic PROFINET IO dispatcher"""
    fields_desc = [
        XShortEnumField("frameID", 0, (i2s_frameid, s2i_frameid))
    ]

    def guess_payload_class(self, payload):
        # For frameID in the RT_CLASS_* range, use the RTC packet as payload
        if (0x0100 <= self.frameID < 0x1000) or (0x8000 <= self.frameID < 0xFC00):
            return PNIORealTimeCyclicPDU
        return super(ProfinetIO, self).guess_payload_class(payload)

bind_layers(Ether, ProfinetIO, type=0x8892)
bind_layers(UDP, ProfinetIO, dport=0x8892)
