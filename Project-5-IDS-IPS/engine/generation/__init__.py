"""
IDS/IPS Traffic Generation Package
==================================

This package contains packet generation components for the IDS/IPS system.
"""

from .packet_sniffer import TrafficGenerator, Packet

__all__ = [
    'TrafficGenerator',
    'Packet'
]