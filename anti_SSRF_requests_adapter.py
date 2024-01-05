import requests
from requests.adapters import HTTPAdapter
import socket
import ipaddress
from urllib.parse import urlparse

class AntiSSRFRequestAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.resolved_ips = {}
        super(AntiSSRFRequestAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        self.poolmanager = requests.packages.urllib3.poolmanager.PoolManager(*args, **kwargs)

    def send(self, request, **kwargs):
        hostname = urlparse(request.url).hostname
        if hostname not in self.resolved_ips:
            try:
                ip = socket.gethostbyname(hostname)
                if ':' in ip:  # Check for IPv6
                    raise ValueError(f"IPv6 addresses are disallowed: {ip}")
                if self.is_disallowed_ip(ip):
                    raise ValueError(f"Access to {request.url} is blocked due to disallowed IP {ip}")
                self.resolved_ips[hostname] = ip
            except socket.gaierror:  # Handle resolution errors
                raise ValueError(f"Error resolving {hostname}")

        return super(AntiSSRFRequestAdapter, self).send(request, **kwargs)

    def is_disallowed_ip(self, ip):
        disallowed_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),
            ipaddress.ip_network('169.254.169.254/32'),
            # Add more ranges as needed
        ]
        ip_addr = ipaddress.ip_address(ip)
        return any(ip_addr in network for network in disallowed_networks)

class AntiSSRFSession:
    def __init__(self):
        self.session = requests.Session()
        adapter = AntiSSRFRequestAdapter()
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def get(self, url, **kwargs):
        kwargs['allow_redirects'] = False
        return self.session.get(url, **kwargs)

    # Implement other HTTP methods here..


assrf_session = AntiSSRFSession()

def main():
    try:
        response = secure_session.get('http://example.com')
        print(response.content)
    except ValueError as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
