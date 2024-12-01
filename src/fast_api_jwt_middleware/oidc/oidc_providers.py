from enum import Enum
from typing import List, Dict, Union


class OIDCProvider(Enum):
    '''
    Enum representing various OpenID Connect (OIDC) providers.

    Each provider is associated with a URL template for its OIDC discovery endpoint
    and a list of required fields needed to construct the URL.

    Attributes:
        OKTA: OIDC provider for Okta, requires 'domain'.
        DUO: OIDC provider for Duo, requires 'domain'.
        ONELOGIN: OIDC provider for OneLogin, requires 'domain'.
        AZURE_AD: OIDC provider for Azure Active Directory, requires 'tenant'.
        AZURE_AD_B2C: OIDC provider for Azure AD B2C, requires 'tenant' and 'policy'.
        GOOGLE: OIDC provider for Google, no additional fields required.
        FACEBOOK: OIDC provider for Facebook, no additional fields required.
        TWITTER: OIDC provider for Twitter, no additional fields required.
        GENERIC: Generic OIDC provider, requires 'base_url'.
        AMAZON_COGNITO: OIDC provider for Amazon Cognito, requires 'user_pool_id' and 'region'.
        AUTH0: OIDC provider for Auth0, requires 'domain'.
        PING_IDENTITY: OIDC provider for Ping Identity, requires 'domain'.
        IBM_SECURITY_VERIFY: OIDC provider for IBM Security Verify, requires 'tenant'.
        SALESFORCE: OIDC provider for Salesforce, requires 'instance'.
        KEYCLOAK: OIDC provider for Keycloak, requires 'domain' and 'realm'.
        GITHUB: OIDC provider for GitHub, no additional fields required.
        LINKEDIN: OIDC provider for LinkedIn, no additional fields required.

    Methods:
        __init__(url_template: str, required_fields: List[str]):
            Initializes the OIDCProvider with a URL template and required fields.
    '''
    OKTA = ('https://{domain}/.well-known/openid-configuration', ['domain'])
    DUO = ('https://{domain}/oauth/v1/.well-known/openid-configuration', ['domain'])
    ONELOGIN = ('https://{domain}/oidc/2/.well-known/openid-configuration', ['domain'])
    AZURE_AD = ('https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration', ['tenant'])
    AZURE_AD_B2C = ('https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration', ['tenant', 'policy'])
    GOOGLE = ('https://accounts.google.com/.well-known/openid-configuration', [])
    FACEBOOK = ('https://www.facebook.com/.well-known/openid-configuration', [])
    GENERIC = ('{base_url}/.well-known/openid-configuration', ['base_url'])
    AMAZON_COGNITO = ('https://{user_pool_id}.auth.{region}.amazoncognito.com/.well-known/openid-configuration', ['user_pool_id', 'region'])
    AUTH0 = ('https://{domain}/.well-known/openid-configuration', ['domain'])
    PING_IDENTITY = ('https://{domain}/.well-known/openid-configuration', ['domain'])
    IBM_SECURITY_VERIFY = ('https://{tenant}.verify.ibm.com/v2.0/.well-known/openid-configuration', ['tenant'])
    SALESFORCE = ('https://{instance}.my.salesforce.com/.well-known/openid-configuration', ['instance'])
    KEYCLOAK = ('https://{domain}/auth/realms/{realm}/.well-known/openid-configuration', ['domain', 'realm'])
    GITHUB = ('https://token.actions.githubusercontent.com/.well-known/openid-configuration', [])

    def __init__(self, url_template: str, required_fields: List[str]):
        self.url_template = url_template
        self.required_fields = required_fields


# Registry for custom providers
CUSTOM_OIDC_PROVIDERS: Dict[str, Dict[str, Union[str, List[str]]]] = {}
'''
A registry for custom OpenID Connect (OIDC) providers.

This dictionary allows users to register custom OIDC providers that are not predefined
in the OIDCProvider enum. Each entry in the dictionary represents a custom provider
with its associated URL template and required fields.

Structure:
    - Key: The name of the custom provider (str).
    - Value: A dictionary containing:
        - 'url_template': The URL template for the provider's OIDC discovery endpoint (str).
        - 'required_fields': A list of fields required to construct the URL (List[str]).

Example:
    CUSTOM_OIDC_PROVIDERS = {
        'CustomProvider': {
            'url_template': 'https://{custom_domain}/.well-known/openid-configuration',
            'required_fields': ['custom_domain']
        }
    }
'''


def register_custom_provider(
    name: str, url_template: str, required_fields: List[str]
):
    '''
    Registers a custom OIDC provider.

    :param name: Name of the custom provider.
    :param url_template: URL template for the custom provider.
    :param required_fields: List of required fields for the provider.
    '''
    if name in CUSTOM_OIDC_PROVIDERS or name in OIDCProvider.__members__:
        raise ValueError(f"Provider '{name}' already exists.")
    if name is None or name.strip() == "":
        raise ValueError(f'Provider name is required.')
    if url_template is None or name.strip() == "":
        raise ValueError(f'Provider url_template is required.')
    CUSTOM_OIDC_PROVIDERS[name] = {
        'url_template': url_template,
        'required_fields': required_fields,
    }

def get_registered_providers() -> Dict[str, Dict[str, Union[str, List[str]]]]:
    """
    Retrieves the currently registered custom OIDC providers.

    :return: A dictionary of registered OIDC providers, where the key is the provider name
             and the value is a dictionary containing 'url_template' and 'required_fields'.
    """
    return CUSTOM_OIDC_PROVIDERS
