"""
Command-line interface for network-traffic-inspector.
"""

import argparse
import json
import sys
from pathlib import Path
from .inspector import Inspector


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze network traffic patterns and communication behaviors"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAP file")
    analyze_parser.add_argument("pcap_file", help="Path to PCAP file")
    analyze_parser.add_argument("--output", "-o", help="Output file path (JSON)")

    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Capture live network traffic")
    capture_parser.add_argument("--interface", "-i", required=True, help="Network interface")
    capture_parser.add_argument("--duration", "-d", type=int, default=60, help="Duration in seconds")
    capture_parser.add_argument("--output", "-o", help="Output PCAP file")

    # Endpoints command
    endpoints_parser = subparsers.add_parser("endpoints", help="Extract endpoints from PCAP")
    endpoints_parser.add_argument("pcap_file", help="Path to PCAP file")
    endpoints_parser.add_argument("--third-party", action="store_true", help="Show only third-party endpoints")
    endpoints_parser.add_argument("--output", "-o", help="Output file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    inspector = Inspector()

    try:
        if args.command == "analyze":
            result = inspector.analyze(args.pcap_file)
            output_data = result.to_dict()

            if args.output:
                with open(args.output, "w") as f:
                    json.dump(output_data, f, indent=2, default=str)
                print(f"Analysis saved to {args.output}")
            else:
                print(result.summary())
                print("\nDetailed Results:")
                print(json.dumps(output_data, indent=2, default=str))

        elif args.command == "capture":
            inspector.capture(args.interface, args.duration, args.output)

        elif args.command == "endpoints":
            result = inspector.analyze(args.pcap_file)
            endpoints = result.third_party_endpoints if args.third_party else result.endpoints

            if args.output:
                with open(args.output, "w") as f:
                    json.dump([e.__dict__ for e in endpoints], f, indent=2, default=str)
                print(f"Endpoints saved to {args.output}")
            else:
                for endpoint in endpoints:
                    print(f"{endpoint.host}:{endpoint.port} ({endpoint.protocol}) - {endpoint.packet_count} packets")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()



