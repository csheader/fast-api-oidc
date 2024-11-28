import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from fast_api_jwt_middleware.oidc_helper import get_oidc_urls, register_custom_provider

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
        expected_url = f"https://{config['tenant']}.b2clogin.com/{config['tenant']}.onmicrosoft.com/v2.0/.well-known/openid-configuration"
        
        urls = get_oidc_urls(domains_or_configs=config, provider_name="AzureAD_B2C")
        self.assertIn(expected_url, urls)

    def test_get_oidc_urls_with_multiple_providers(self):
        """Test getting OIDC URLs for multiple providers."""
        configs = [
            {"tenant": "tenant1", "policy": "policy1"},
            {"tenant": "tenant2", "policy": "policy2"}
        ]
        expected_urls = [
            f"https://{config['tenant']}.b2clogin.com/{config['tenant']}.onmicrosoft.com/v2.0/.well-known/openid-configuration"
            for config in configs
        ]
        
        urls = get_oidc_urls(domains_or_configs=configs, provider_name="AzureAD_B2C")
        for expected_url in expected_urls:
            self.assertIn(expected_url, urls)

    def test_register_custom_provider(self):
        """Test registering a custom OIDC provider."""
        provider_name = "CustomProvider"
        url_template = "https://{custom_domain}/.well-known/openid-configuration"
        required_fields = ["custom_domain"]

        # Register the custom provider
        register_custom_provider(name=provider_name, url_template=url_template, required_fields=required_fields)

        # Check if the provider is registered correctly
        # This part will depend on how you store registered providers
        # For example, if you have a global dictionary to store them:
        # self.assertIn(provider_name, registered_providers)

    def test_register_custom_provider_invalid(self):
        """Test registering a custom OIDC provider with missing fields."""
        with self.assertRaises(ValueError):
            register_custom_provider(name="", url_template="", required_fields=[])

if __name__ == "__main__":
    unittest.main()