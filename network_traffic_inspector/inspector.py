"""
Main inspector class for network traffic analysis.
"""

import time
import socket
from pathlib import Path
from typing import List, Dict, Set, Optional
from collections import defaultdict
from .models import Packet, Endpoint, TrafficAnalysis

try:
    from scapy.all import rdpcap, IP, TCP, UDP, TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class Inspector:
    """Main inspector class for network traffic analysis."""

    def __init__(self):
        """Initialize the inspector."""
        self.third_party_domains = self._load_third_party_domains()

    def analyze(self, pcap_file: str) -> TrafficAnalysis:
        """
        Analyze a PCAP file and extract traffic information.

        Args:
            pcap_file: Path to the PCAP file

        Returns:
            TrafficAnalysis object containing analysis results
        """
        start_time = time.time()
        pcap_path = Path(pcap_file)

        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy is required for packet analysis. Install it with: pip install scapy"
            )

        packets = self._load_packets(pcap_path)
        endpoints = self._extract_endpoints(packets)
        protocols = self._analyze_protocols(packets)
        encrypted_count, unencrypted_count = self._analyze_encryption(packets)
        third_party = self._identify_third_party(endpoints)

        analysis_duration = time.time() - start_time

        return TrafficAnalysis(
            total_packets=len(packets),
            total_bytes=sum(p.size for p in packets),
            endpoints=endpoints,
            protocols=protocols,
            encrypted_count=encrypted_count,
            unencrypted_count=unencrypted_count,
            third_party_endpoints=third_party,
            analysis_duration=analysis_duration,
        )

    def capture(self, interface: str, duration: int = 60, output: Optional[str] = None):
        """
        Capture live network traffic.

        Args:
            interface: Network interface to capture on
            duration: Duration in seconds
            output: Output file path for captured packets
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required for packet capture")

        try:
            from scapy.all import sniff

            print(f"Capturing on {interface} for {duration} seconds...")
            packets = sniff(iface=interface, timeout=duration)

            if output:
                from scapy.all import wrpcap
                wrpcap(output, packets)
                print(f"Captured {len(packets)} packets, saved to {output}")
            else:
                print(f"Captured {len(packets)} packets")

            return packets
        except Exception as e:
            raise RuntimeError(f"Failed to capture packets: {e}")

    def _load_packets(self, pcap_path: Path) -> List[Packet]:
        """Load packets from PCAP file."""
        packets = []
        try:
            scapy_packets = rdpcap(str(pcap_path))
            for pkt in scapy_packets:
                packet = self._parse_packet(pkt)
                if packet:
                    packets.append(packet)
        except Exception as e:
            raise RuntimeError(f"Failed to load PCAP file: {e}")

        return packets

    def _parse_packet(self, pkt) -> Optional[Packet]:
        """Parse a scapy packet into our Packet model."""
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = None
                dst_port = None
                protocol = "IP"

                if TCP in pkt:
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    encrypted = self._is_encrypted_tcp(pkt)
                elif UDP in pkt:
                    protocol = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    encrypted = False
                else:
                    encrypted = False

                return Packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    size=len(pkt),
                    encrypted=encrypted,
                )
        except Exception:
            pass

        return None

    def _is_encrypted_tcp(self, pkt) -> bool:
        """Check if TCP packet is encrypted (TLS/SSL)."""
        try:
            return TLS in pkt
        except Exception:
            return False

    def _extract_endpoints(self, packets: List[Packet]) -> List[Endpoint]:
        """Extract unique endpoints from packets."""
        endpoint_map: Dict[tuple, Endpoint] = {}

        for packet in packets:
            # Use destination as endpoint
            key = (packet.dst_ip, packet.dst_port, packet.protocol)
            if key not in endpoint_map:
                endpoint_map[key] = Endpoint(
                    host=packet.dst_ip,
                    port=packet.dst_port,
                    protocol=packet.protocol,
                )

            endpoint = endpoint_map[key]
            endpoint.packet_count += 1
            endpoint.total_bytes += packet.size

            # Try to resolve domain
            if not endpoint.domain:
                try:
                    endpoint.domain = socket.gethostbyaddr(packet.dst_ip)[0]
                except Exception:
                    pass

        return list(endpoint_map.values())

    def _analyze_protocols(self, packets: List[Packet]) -> Dict[str, int]:
        """Analyze protocol distribution."""
        protocols = defaultdict(int)
        for packet in packets:
            protocols[packet.protocol] += 1
        return dict(protocols)

    def _analyze_encryption(self, packets: List[Packet]) -> tuple:
        """Analyze encryption usage."""
        encrypted = sum(1 for p in packets if p.encrypted)
        unencrypted = len(packets) - encrypted
        return encrypted, unencrypted

    def _identify_third_party(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """Identify third-party endpoints."""
        third_party = []
        for endpoint in endpoints:
            if endpoint.domain:
                if self._is_third_party_domain(endpoint.domain):
                    endpoint.is_third_party = True
                    third_party.append(endpoint)
        return third_party

    def _is_third_party_domain(self, domain: str) -> bool:
        """Check if domain is a known third-party service."""
        domain_lower = domain.lower()
        third_party_indicators = [
            "google-analytics",
            "facebook",
            "twitter",
            "analytics",
            "tracking",
            "advertising",
            "ads",
        ]
        return any(indicator in domain_lower for indicator in third_party_indicators)

    def _load_third_party_domains(self) -> Set[str]:
        """Load known third-party domains."""
        # This would typically load from a comprehensive list
        return set()


