import subprocess
import re
import os
import getpass
import requests
from time import sleep

class NetstatOutput:
    def __init__(self):
        self.command = "netstat -tulnpa -4"
        self.api_key = self.set_api_key()
        self.max_checks_per_minute = 4
        self.checks_counter = 0

    def set_api_key(self):
        os.environ['VT_ApiKey'] = getpass.getpass('Please enter correct API key for VirusTotal: ')
        return os.environ['VT_ApiKey']

    def get_netstat_output(self):
        try:
            process = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            return stdout.decode()
        except Exception as e:
            print(f'Error occurred while running netstat command: {e}')
            return None

    def extract_ips(self, netstat_output):
        if not netstat_output:
            return []
        ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', netstat_output)
        return [ip for ip in ip_addresses if not (ip.startswith('172.16.') or ip.startswith('192.168.') or ip.startswith('10.0') or ip == '127.0.0.1' or ip == '0.0.0.0')]

    def virustotal_api(self, ip_addresses):
        for ip in ip_addresses:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'   
            headers = {'x-apikey': self.api_key}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                full_score = sum(data['data']['attributes']['last_analysis_stats'].values())
                malicious_score = data['data']['attributes']['last_analysis_stats']['malicious']
                print(f'Total score for IP {ip}: {malicious_score}/{full_score}')
            else:
                print(f"Error: {response.status_code}")

    def run_checks(self):
        netstat_output = self.get_netstat_output()
        if not netstat_output:
            return
        ip_addresses = self.extract_ips(netstat_output)
        for ip in ip_addresses:
            if self.checks_counter == self.max_checks_per_minute:
                print("You have reached the API rate limit. Waiting 60 seconds...")
                sleep(60)
                self.checks_counter = 0
            self.virustotal_api([ip])
            self.checks_counter += 1


netstat = NetstatOutput()
netstat.run_checks()
