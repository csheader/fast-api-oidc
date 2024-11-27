from .oidc_providers import OIDCProvider, CUSTOM_OIDC_PROVIDERS
from typing import List

def get_oidc_urls(domains_or_configs: List[dict] | dict, provider_name: str) -> List[str]:
    '''
    Constructs OIDC discovery URLs for both built-in and custom providers.

    :param domains_or_configs: List of dictionaries containing provider-specific configuration.
    :param provider_name: Name of the provider (can be built-in or custom).
    :return: List of OIDC discovery URLs.
    '''
    if isinstance(domains_or_configs, dict):
        domains_or_configs = [domains_or_configs]
    if provider_name in OIDCProvider.__members__:
        provider = OIDCProvider[provider_name]
        url_template = provider.url_template
        required_fields = provider.required_fields
    elif provider_name in CUSTOM_OIDC_PROVIDERS:
        provider = CUSTOM_OIDC_PROVIDERS[provider_name]
        url_template = provider['url_template']
        required_fields = provider['required_fields']
    else:
        raise ValueError(f"Unknown provider '{provider_name}'.")

    # Validate input and generate URLs
    oidc_urls = []
    for config in domains_or_configs:
        if not isinstance(config, dict):
            raise ValueError(f'Configuration for {provider_name} must be a dictionary.')
        missing_fields = [field for field in required_fields if field not in config]
        if missing_fields:
            raise ValueError(f'Missing required fields {missing_fields} for {provider_name}.')
        oidc_urls.append(url_template.format(**config))

    return oidc_urls
