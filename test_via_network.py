
"""
additionaly to the unit tests some real test seem nececary
Test security controlls:
* IPv6 blocking
* a few NAT request
* some HTTP redirects
* fetch some Rebinding URL

* Test the propper functioning of allowed requests:
    briefly test all HTTP verbs, after adding :D

"""

import socket
import requests
from unittest.mock import patch
import unittest
from anti_SSRF_requests_adapter import AntiSSRFRequestAdapter, AntiSSRFSession, NetworkSecurityViolationError

import netifaces

assrf_session = AntiSSRFSession()


### seems better than below
def is_ipv6_supported_2():
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET6 in addresses:
            for link in addresses[netifaces.AF_INET6]:
                if 'addr' in link:
                    return True
    return False


### this does not work ....
def is_ipv6_supported():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    except OSError as e:
        return False
    finally:
        s.close()

class TestAntiSSRFRequestAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = AntiSSRFRequestAdapter()
        self.session = requests.Session()
        self.session.mount('http://', self.adapter)
        self.session.mount('https://', self.adapter)


    #@patch('socket.gethostbyname')
    #def test_resolution_of_valid_hostname(self, mock_gethostbyname):
    #   mock_gethostbyname.return_value = '93.184.216.34'
    #    response = self.session.get('http://example.com')
    #    self.assertEqual(response.status_code, 200)

    def test_normal_get(self):
        response = assrf_session.get('http://example.com')
        #    #print(response.content)
        #except ValueError as e:
        #    print(f"An error occurred: {e}. Test failed")


    def test_alternatibe_ip_notations(self):
        """ note that all these cases __should__ all be handeled by socket.gethostbyname()"""

        ip_address_variants = [
            "192.168.0.1",          # Standard Dotted Decimal
            "0300.0250.00.01",      # Octal Representation
            "0xC0.0xA8.0x0.0x1",    # Hexadecimal Representation
            # "11000000.10101000.00000000.00000001",  ## python's socket.gethostbyname() can't understand bin
                                    # Binary Representation
            "3232235521",           # Integer Representation
            "192.168.000.001",      # Padded Notation
            "0xC0.168.0.1",         # Mixed Hexadecimal and Decimal
            "0300.168.00.01",       # Mixed Octal and Decimal
            # "::ffff:192.168.0.1",   # IPv6 Mapped IPv4 Address  ## fails to parse, good
            #"1921680001"            # Decimal with No Dots  this one resolved to 114.138.130.129???
        ]


        for ip in ip_address_variants:
            print(f"testing: {ip}")
            with self.assertRaises(NetworkSecurityViolationError):
                #self.session.get('http://privateaddress.com')
                assrf_session.get(f"http://{ip}:9999/foo")


    def test_ipv6(self):
        if not is_ipv6_supported_2():
            print("Test 'test_ipv6_to_4_mapped' non conclusive. IP v6 test failes due to OS not due to lib")
            return None
        print("has!!")
        with self.assertRaises(NetworkSecurityViolationError):
            response = assrf_session.get("http://[2a00:1450:4026:803::200e]/")

    def test_ipv6_to_4_mapped(self):
        if not is_ipv6_supported_2():
            print("Test 'test_ipv6_to_4_mapped' non conclusive. IP v6 test failes due to OS not due to lib")
            return None
        with self.assertRaises(NetworkSecurityViolationError):
            try:
                response = assrf_session.get("http://[::ffff:192.168.0.1]/")
            except ValueError:
                raise NetworkSecurityViolationError


if __name__ == '__main__':
    unittest.main()
