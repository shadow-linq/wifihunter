WiFi Vulnerability Scanner
Analyzes one or more pcap files for common WiFi security vulnerabilities.

Usage:
    python wifi_vuln_scanner.py capture.pcap [capture2.pcap ...] --ssids SSID1 SSID2
    python wifi_vuln_scanner.py *.pcap --all-ssids

Requirements:
    pip install scapy