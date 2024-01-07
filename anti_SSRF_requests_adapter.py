import ssl

import requests
from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK, DEFAULT_POOLSIZE, DEFAULT_RETRIES, BaseAdapter
import socket
import ipaddress
from urllib.parse import urlparse, urlunparse
import certifi

from urllib3 import PoolManager, Retry


class AntiSSRFRequestAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        super(AntiSSRFRequestAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        self.poolmanager = requests.packages.urllib3.poolmanager.PoolManager(*args, **kwargs)


class AntiSSRFSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.mount('http://', AntiSSRFRequestAdapter())
        self.session.mount('https://', AntiSSRFRequestAdapter())

    def get(self, url, **kwargs):
        kwargs['allow_redirects'] = False
        parsedURL = urlparse(url)
        hostname = parsedURL.hostname
        # first validate hostname SSL because we want to send the https request directly to IP address
        self.verify_ssl_certificate(hostname)
        ip = ""
        if hostname:
            try:
                ip = socket.gethostbyname(hostname)
                if ':' in ip:  # Check for IPv6
                    raise ValueError(f"IPv6 addresses are disallowed: {ip}")
                if self.is_disallowed_ip(ip):
                    raise ValueError(f"Access to {url} is blocked due to disallowed IP {ip}")
            except socket.gaierror:  # Handle resolution errors
                raise ValueError(f"Error resolving {hostname}")
        if parsedURL.port:
            new_url = urlunparse(
                (parsedURL.scheme, ip + ":" + str(parsedURL.port), parsedURL.path, parsedURL.params,
                 parsedURL.query, parsedURL.fragment))
        else:
            new_url = urlunparse(
                (parsedURL.scheme, ip, parsedURL.path, parsedURL.params,
                 parsedURL.query, parsedURL.fragment))
        return self.session.get(new_url, headers={"host": hostname},
                                **kwargs)

    def is_disallowed_ip(self, ip):
        disallowed_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),
            # what other ranges are relevant?
        ]
        ip_addr = ipaddress.ip_address(ip)
        return any(ip_addr in network for network in disallowed_networks)

    def verify_ssl_certificate(self, hostname):
        context = ssl.create_default_context(cafile=certifi.where())

        with socket.create_connection((hostname, 443)) as sock:
            try:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.do_handshake()
                    ssock.getpeercert()
            except ssl.SSLCertVerificationError as err:
                raise ValueError(f"Error validating SSL {hostname}")
            print("Certificate is valid.")

    # TBD: Implement other HTTP methods here..


assrf_session = AntiSSRFSession()


def main():
    try:
        response = assrf_session.get('https://www.google.com/', verify=False)
        print(response.content)
        # response = requests.get('https://google.com/')
        # print(response.content)
    except ValueError as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
