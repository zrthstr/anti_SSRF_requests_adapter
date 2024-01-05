
import unittest
from unittest.mock import patch
#import responses
from anti_SSRF_requests_adapter import AntiSSRFRequestAdapter, AntiSSRFSession
import requests

class TestAntiSSRFRequestAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = AntiSSRFRequestAdapter()
        self.session = requests.Session()
        self.session.mount('http://', self.adapter)
        self.session.mount('https://', self.adapter)

    @patch('socket.gethostbyname')
    def test_resolution_of_valid_hostname(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '93.184.216.34'
        response = self.session.get('http://example.com')
        self.assertEqual(response.status_code, 200)

    @patch('socket.gethostbyname')
    def test_blocking_disallowed_ips(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '192.168.1.1'
        with self.assertRaises(ValueError):
            self.session.get('http://privateaddress.com')

    @patch('socket.gethostbyname')
    def test_handling_ipv6_addresses(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        with self.assertRaises(ValueError):
            self.session.get('http://ipv6address.com')

    @patch('socket.gethostbyname')
    def test_dns_rebinding_protection(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '93.184.216.34'

        self.session.get('http://example.com')
        self.assertEqual(mock_gethostbyname.call_count, 1)


if __name__ == '__main__':
    unittest.main()

