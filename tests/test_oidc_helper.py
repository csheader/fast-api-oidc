import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from fast_api_jwt_middleware.oidc.oidc_helper import get_oidc_urls

class TestOIDCHelper(unittest.TestCase):

    def setUp(self):
        """Set up any necessary state before each test."""
        # You can set up any necessary state here if needed
        pass

    def test_get_oidc_urls_with_single_provider(self):
        """Test getting OIDC URLs for a single provider."""
        config = {
            "tenant": "your-tenant-name",
            "policy": "policy1"
        }
        expected_url = f"https://{config['tenant']}.b2clogin.com/{config['tenant']}.onmicrosoft.com/{config['policy']}/v2.0/.well-known/openid-configuration"
        
        urls = get_oidc_urls(domains_or_configs=config, provider_name="AZURE_AD_B2C")
        self.assertIn(expected_url, urls)

    def test_get_oidc_urls_with_multiple_providers(self):
        """Test getting OIDC URLs for multiple providers."""
        configs = [
            {"tenant": "tenant1", "policy": "policy1"},
            {"tenant": "tenant2", "policy": "policy2"}
        ]
        expected_urls = [
            f"https://{config['tenant']}.b2clogin.com/{config['tenant']}.onmicrosoft.com/{config['policy']}/v2.0/.well-known/openid-configuration"
            for config in configs
        ]
        
        urls = get_oidc_urls(domains_or_configs=configs, provider_name="AZURE_AD_B2C")
        for expected_url in expected_urls:
            self.assertIn(expected_url, urls)


if __name__ == "__main__":
    unittest.main()