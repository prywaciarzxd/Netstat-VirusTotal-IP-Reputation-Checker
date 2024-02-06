import subprocess
import re
import os
import getpass
import requests
from time import sleep

class NestatOutput:
    def __init__(self):
        self.command = "netstat -tulnpa -4"
        self.api_key = self.set_env_var()
        self.counter = 0
        

    def set_env_var(self):
        os.environ['VT_ApiKey'] = getpass.getpass('Please enter correct api key to virustotal: ')
        return os.environ['VT_ApiKey']

    def create_process(self):
        try:
            self.process = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = self.process.communicate()
            output, err_output = stdout.decode(), stderr.decode()
            return output, err_output
        except: 
            print('There was an error!')
    
    def extract_ips(self):
        output, err_output = self.create_process()
        ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output)
        ip_addresses = list(filter(lambda ip: not (ip.startswith('172.16.') or ip.startswith('192.168.') or ip.startswith('10.0') or ip == '127.0.0.1' or ip == '0.0.0.0'), ip_addresses))
        return ip_addresses
    
    def virustotal_api(self):
        ip_addresses = self.extract_ips()
        for ip in ip_addresses:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'   
            headers = {
                'x-apikey': self.api_key
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200 and self.counter != 4:
                data = response.json()
                full_score = sum(data['data']['attributes']['last_analysis_stats'].values())
                malicious_score = data['data']['attributes']['last_analysis_stats']['malicious']
                print(f'Total score for this ip: {ip} is {malicious_score}/{full_score}')
                ip_addresses.remove(ip)
                self.counter += 1
            elif response.status_code == 200 and self.counter == 4:
                print("You have free api version of virsutotal, only 4 checks per minute permitted! Please, wait!")
                self.counter = 0
                sleep(60)
            else:
                print(f"Error: {response.status_code}")

            
                



netstat = NestatOutput()
netstat.virustotal_api()