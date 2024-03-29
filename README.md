# Netstat-VirusTotal-IP-Reputation-Checker

Welcome to the Netstat-VirusTotal-IP-Reputation-Checker repository!

This Python script is designed to facilitate the analysis of active network connections on your system by utilizing the 'netstat' command and the VirusTotal API to assess the reputation of IP addresses. With this tool, you can quickly check whether your network connections are secure and do not exhibit suspicious behavior.

## Main Features:
- Analyze active network connections using the 'netstat' command.
- Check the reputation of IP addresses using the VirusTotal API.
- Detect potentially harmful connections based on feedback from VirusTotal.

## New Feature:
- Added functionality for users to check individual IP addresses by passing them as command-line arguments using the `--ips` flag. Now you can specify specific IP addresses to analyze their reputation.

## Requirements:
- Python 3.x
- requests package
- VirusTotal account and API key (for full functionality)
- Currently only on Linux machines

## How to Use:
1. Run the `check_connections.py` script.
2. Optionally, pass individual IP addresses as command-line arguments using the `--ips` flag, separated by spaces or commas.
3. The script will automatically gather information about active connections and assess the reputation of IP addresses.
4. You will receive a report containing information about each connection and its reputation from VirusTotal.

## License:
This project is licensed under the MIT License. See the LICENSE file for more information.
