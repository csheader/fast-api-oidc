import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from fast_api_jwt_middleware.oidc_providers import register_custom_provider, get_registered_providers

class TestOIDCProviders(unittest.TestCase):

    def setUp(self):
        """Set up any necessary state before each test."""
        # Clear any previously registered providers if applicable
        # This assumes you have a way to clear registered providers
        # For example, if you have a global list or dictionary to store them
        self.clear_registered_providers()

    def clear_registered_providers(self):
        """Helper method to clear registered providers for testing."""
        # This function should clear the registered providers
        # Implement this based on how you store registered providers
        pass

    def test_register_custom_provider(self):
        """Test registering a custom OIDC provider."""
        provider_name = "CustomProvider"
        url_template = "https://{custom_domain}/.well-known/openid-configuration"
        required_fields = ["custom_domain"]

        # Register the custom provider
        register_custom_provider(name=provider_name, url_template=url_template, required_fields=required_fields)

        # Check if the provider is registered correctly
        registered_providers = get_registered_providers()  # Assuming this function returns the list of registered providers
        self.assertIn(provider_name, registered_providers)

    def test_register_custom_provider_invalid(self):
        """Test registering a custom OIDC provider with missing fields."""
        with self.assertRaises(ValueError):
            register_custom_provider(name="", url_template="", required_fields=[])

    def test_register_duplicate_provider(self):
        """Test registering a duplicate OIDC provider."""
        provider_name = "DuplicateProvider"
        url_template = "https://{custom_domain}/.well-known/openid-configuration"
        required_fields = ["custom_domain"]

        # Register the provider the first time
        register_custom_provider(name=provider_name, url_template=url_template, required_fields=required_fields)

        # Attempt to register the same provider again
        with self.assertRaises(ValueError):
            register_custom_provider(name=provider_name, url_template=url_template, required_fields=required_fields)

    def test_get_registered_providers_empty(self):
        """Test getting registered providers when none are registered."""
        self.clear_registered_providers()  # Ensure no providers are registered
        registered_providers = get_registered_providers()
        self.assertEqual(registered_providers, {})

if __name__ == "__main__":
    unittest.main()