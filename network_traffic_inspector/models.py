"""
Data models for network traffic analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class Packet:
    """Represents a network packet."""

    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "unknown"
    size: int = 0
    timestamp: Optional[datetime] = None
    encrypted: bool = False
    payload: Optional[bytes] = None


@dataclass
class Endpoint:
    """Represents a network endpoint."""

    host: str
    port: Optional[int] = None
    protocol: str = "unknown"
    packet_count: int = 0
    total_bytes: int = 0
    is_third_party: bool = False
    domain: Optional[str] = None


@dataclass
class TrafficAnalysis:
    """Result of traffic analysis."""

    total_packets: int
    total_bytes: int
    endpoints: List[Endpoint]
    protocols: Dict[str, int]
    encrypted_count: int
    unencrypted_count: int
    third_party_endpoints: List[Endpoint]
    analysis_duration: float

    def summary(self) -> str:
        """Generate a summary of the analysis."""
        return f"""
Traffic Analysis Summary
Total Packets: {self.total_packets}
Total Bytes: {self.total_bytes}
Unique Endpoints: {len(self.endpoints)}
Third-Party Endpoints: {len(self.third_party_endpoints)}
Encrypted Packets: {self.encrypted_count}
Unencrypted Packets: {self.unencrypted_count}
Protocols: {', '.join(self.protocols.keys())}
        """.strip()

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "endpoints": [
                {
                    "host": e.host,
                    "port": e.port,
                    "protocol": e.protocol,
                    "packet_count": e.packet_count,
                    "total_bytes": e.total_bytes,
                    "is_third_party": e.is_third_party,
                    "domain": e.domain,
                }
                for e in self.endpoints
            ],
            "protocols": self.protocols,
            "encrypted_count": self.encrypted_count,
            "unencrypted_count": self.unencrypted_count,
            "third_party_endpoints": [
                {
                    "host": e.host,
                    "port": e.port,
                    "domain": e.domain,
                }
                for e in self.third_party_endpoints
            ],
            "analysis_duration": self.analysis_duration,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)


