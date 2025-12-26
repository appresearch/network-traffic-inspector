"""
Network Traffic Inspector - Advanced network traffic analysis tool.
"""

__version__ = "1.8.3"
__author__ = "Applied Science Research Institute"

from .inspector import Inspector
from .models import Packet, Endpoint, TrafficAnalysis

__all__ = ["Inspector", "Packet", "Endpoint", "TrafficAnalysis"]



