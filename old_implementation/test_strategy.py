# Example test structure for dns_checks.py
import unittest
from unittest.mock import patch
from scanner.dns_checks import check_dnssec

class TestDNSChecks(unittest.TestCase):
    @patch('dns.resolver.resolve')
    def test_check_dnssec(self, mock_resolve):
        # Mock setup
        mock_resolve.return_value = ['sample_dnskey']
        
        # Test
        result = check_dnssec('example.com')
        
        # Assert
        self.assertTrue(result['enabled'])
        self.assertEqual(result['status'], 'success')
