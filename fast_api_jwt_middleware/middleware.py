"""
middleware.py

This module provides middleware classes for handling authentication in FastAPI applications using JWT tokens.
It includes support for single and multiple OIDC (OpenID Connect) providers.

Classes:
    - AuthMiddleware: Middleware for handling authentication with a single OIDC provider.
    - MultiProviderAuthMiddleware: Middleware for handling authentication with multiple OIDC providers.

The middleware classes utilize caching for OIDC configurations, JWKS (JSON Web Key Sets), and tokens to
optimize performance and reduce the number of network requests.

Dependencies:
    - fastapi: For handling HTTP requests and responses.
    - starlette: For base middleware functionality.
    - cachetools: For caching OIDC configurations, JWKS, and tokens.
    - requests: For making HTTP requests to fetch OIDC configurations and JWKS.
    - jwt: For decoding and validating JWT tokens.
    - os: For accessing environment variables.
    - log_interceptor: For logging purposes.
"""

from typing import List, Dict, Union, Optional
from cachetools import TTLCache
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import requests
import jwt
import os
from .log_interceptor import Logger

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle authentication for a single provider with multiple OIDC URLs.

    Attributes:
        app (ASGIApp): FastAPI application.
        oidc_urls (List[str]): List of well-known OIDC URLs for the IDP.
        audiences (List[str]): The audience to validate tokens against.
        token_cache (TTLCache): Cache for storing validated tokens.
        jwks_cache (Dict[str, TTLCache]): Cache for storing JWKS data.
        oidc_config_cache (TTLCache): Cache for storing OIDC configuration data.
        supported_algorithms (Dict[str, List[str]]): Supported signing algorithms for each OIDC URL.
        logger (Logger): Logger instance for logging messages.
    """
    def __init__(
        self,
        app: ASGIApp,
        oidc_urls: List[str],
        audiences: List[str],
        token_ttl: int = 300,
        jwks_ttl: int = 3600,
        oidc_ttl: int = 3600,
        token_cache_maxsize: int = 1000,
        logger: Optional[object] = None
    ) -> None:
        """
        Middleware to handle authentication for a single provider with multiple OIDC URLs.

        :param app: FastAPI application.
        :param oidc_urls: List of well-known OIDC URLs for the IDP.
        :param audience: The audience to validate tokens against.
        :param token_ttl: Time-to-live for token cache (in seconds).
        :param jwks_ttl: Time-to-live for JWKS cache (in seconds).
        :param oidc_ttl: Time-to-live for OIDC configuration cache (in seconds).
        :param token_cache_maxsize: Maximum size of the token cache.
        """
        super().__init__(app)
        self.oidc_urls: List[str] = oidc_urls
        self.audiences: str = audiences
        self.token_cache: TTLCache = TTLCache(maxsize=token_cache_maxsize, ttl=token_ttl)
        self.jwks_cache: Dict[str, TTLCache] = {
            oidc_url: TTLCache(maxsize=10, ttl=jwks_ttl) for oidc_url in oidc_urls
        }
        self.oidc_config_cache: TTLCache = TTLCache(maxsize=len(oidc_urls), ttl=oidc_ttl)
        self.supported_algorithms: Dict[str, List[str]] = self.get_supported_algorithms()
        self.logger = Logger(logger)

    def get_oidc_config(self, oidc_url: str) -> Dict[str, Union[str, List[str]]]:
        """
        Fetches and caches OIDC configuration data.

        :param oidc_url: The well-known OIDC URL.
        :return: OIDC configuration data.
        """
        if oidc_url in self.oidc_config_cache:
            return self.oidc_config_cache[oidc_url]
        
        self.logger.debug(f'fetching OIDC configuration: {oidc_url}')
        response = requests.get(oidc_url)
        if response.status_code == 200:
            oidc_config = response.json()
            self.oidc_config_cache[oidc_url] = oidc_config
            return oidc_config

        response.raise_for_status()

    def get_supported_algorithms(self) -> Dict[str, List[str]]:
        """
        Fetches supported signing algorithms for each OIDC URL.

        :return: Dictionary of OIDC URLs and their supported algorithms.
        """
        supported_algorithms = {}
        for oidc_url in self.oidc_urls:
            oidc_config = self.get_oidc_config(oidc_url)
            supported_algorithms[oidc_url] = oidc_config.get("id_token_signing_alg_values_supported", ["RS256"])
        return supported_algorithms

    def get_jwks(self, oidc_url: str) -> Dict[str, Union[str, List[Dict[str, str]]]]:
        """
        Fetches and caches JWKS data.

        :param oidc_url: The well-known OIDC URL.
        :return: JWKS data.
        """
        oidc_config = self.get_oidc_config(oidc_url)
        jwks_uri = oidc_config.get("jwks_uri")
        if not jwks_uri:
            raise ValueError(f"JWKS URI not found for OIDC URL: {oidc_url}")

        if jwks_uri in self.jwks_cache[oidc_url]:
            return self.jwks_cache[oidc_url][jwks_uri]

        self.logger.debug(f'jwks url found for {oidc_url}, getting the jwks keys for the IdP. Fetched JWKS URI: {jwks_uri}')
        response = requests.get(jwks_uri)
        if response.status_code == 200:
            jwks_data = response.json()
            self.jwks_cache[oidc_url][jwks_uri] = jwks_data
            return jwks_data

        response.raise_for_status()

    def decode_token(self, token: str) -> Dict[str, Union[str, List[str]]]:
        """
        Decode and validate a token based on matching JWKS 'kid'.

        :param token: The token to decode.
        :return: Decoded token data.
        """
        # Check if the token is already cached
        if token in self.token_cache:
            self.logger.debug('token found in cache')
            return self.token_cache[token]

        # Extract the kid from the token's header
        unverified_header = jwt.get_unverified_header(token)
        token_kid = unverified_header.get("kid")
        if not token_kid:
            self.logger.error('The token header does not contain a kid, the token is invalid.')
            raise ValueError("Token header does not contain 'kid'.")

        # Search for the matching JWKS key across all OIDC URLs
        for oidc_url in self.oidc_urls:
            jwks = self.get_jwks(oidc_url)
            public_keys = {key["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(key) for key in jwks["keys"]}
            if token_kid in public_keys:
                try:
                    key = public_keys[token_kid]
                    decoded_token = jwt.decode(
                        token,
                        key=key,
                        algorithms=self.supported_algorithms[oidc_url],
                        audience=self.audiences,
                        options={"verify_exp": True}
                    )
                    self.logger.debug('Token valid, caching token for future use.')
                    self.token_cache[token] = decoded_token
                    return decoded_token
                except jwt.PyJWTError as e:
                    self.logger.error(f'Token validation failed: {str(e)}')
                    raise ValueError('Token invalid.')

        # No valid kid found from the token, this should be kicked back with an exception
        self.log_error("Token validation failed: Key not found. This usually means that the token is from an IdP that is not within your supported IdP's from your API.")
        raise ValueError("Invalid token: Key not found")

    async def dispatch(self, request: Request, call_next) -> JSONResponse:
        """
        Middleware handler to authenticate and attach user info to the request state.
        """
        token = request.headers.get("Authorization")
        if token:
            token = token.replace("Bearer ", "")
            try:
                user_data = self.decode_token(token)
                request.state.user = user_data
            except Exception as e:
                return JSONResponse({"detail": str(e)}, status_code=401)
        else:
            request.state.user = None
        return await call_next(request)

class MultiProviderAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle authentication for multiple providers.

    Attributes:
        app (ASGIApp): FastAPI application.
        providers (List[Dict]): List of provider configurations, each including:
            - oidc_urls: List of well-known OIDC URLs
            - audiences: List of audiences to validate tokens against
            - roles_key (optional): The claim key for roles (default: 'roles')
        token_cache (TTLCache): Cache for storing validated tokens.
        jwks_cache (Dict[str, TTLCache]): Cache for storing JWKS data.
        oidc_config_cache (TTLCache): Cache for storing OIDC configuration data.
        logger (Logger): Logger instance for logging messages.
    """
    def __init__(
        self,
        app: ASGIApp,
        providers: List[Dict[str, Union[List[str], str]]],
        token_ttl: int = 300,
        jwks_ttl: int = 3600,
        oidc_ttl: int = 3600,
        token_cache_maxsize: int = 1000,
        logger: Optional[object] = None,
    ):
        """
        Middleware to handle authentication for multiple providers.

        :param app: FastAPI application.
        :param providers: List of provider configurations, each including:
            - oidc_urls: List of well-known OIDC URLs
            - audiences: List of audiences to validate tokens against
            - roles_key (optional): The claim key for roles (default: 'roles')
        :param token_ttl: Time-to-live for token cache (in seconds).
        :param jwks_ttl: Time-to-live for JWKS cache (in seconds).
        :param oidc_ttl: Time-to-live for OIDC configuration cache (in seconds).
        :param token_cache_maxsize: Maximum size of the token cache.
        :param logger: Optional logger instance.
        """
        super().__init__(app)
        self.providers = providers
        self.token_cache = TTLCache(maxsize=token_cache_maxsize, ttl=token_ttl)
        self.jwks_cache = {}
        self.oidc_config_cache = TTLCache(maxsize=len(providers), ttl=oidc_ttl)
        self.logger = Logger(logger)

        # Initialize JWKS caches for each OIDC URL
        for provider in providers:
            for oidc_url in provider["oidc_urls"]:
                self.jwks_cache[oidc_url] = TTLCache(maxsize=10, ttl=jwks_ttl)

    def get_provider_for_token(self, token: str) -> Optional[Dict]:
        """
        Determine which provider's OIDC URLs and audiences match the given token.

        :param token: The JWT token.
        :return: The matching provider configuration or None.
        """
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
        for provider in self.providers:
            if unverified_claims.get("aud") in provider["audiences"]:
                return provider
        return None

    async def dispatch(self, request: Request, call_next):
        """
        Middleware handler to authenticate and attach user info to the request state.
        """
        token = request.headers.get("Authorization")
        if token:
            token = token.replace("Bearer ", "")
            provider = self.get_provider_for_token(token)
            if provider:
                try:
                    user_data = self.decode_token(token, provider)
                    request.state.user = {
                        "token": token,
                        "roles": user_data.get(provider.get("roles_key", "roles"), []),
                        "provider": provider,
                    }
                    return await call_next(request)
                except Exception as e:
                    self.logger.error(f"Authentication failed: {e}")
                    return JSONResponse({"detail": "Invalid or unauthorized token"}, status_code=401)

        # No token or no matching provider
        request.state.user = None
        return await call_next(request)

    def decode_token(self, token: str, provider: Dict) -> Dict[str, Union[str, List[str]]]:
        """
        Decode and validate a token for a specific provider.

        :param token: The JWT token.
        :param provider: The provider configuration.
        :return: Decoded token data.
        """
        # Check cache
        if token in self.token_cache:
            self.logger.debug("Token found in cache")
            return self.token_cache[token]

        # Get JWKS keys
        for oidc_url in provider["oidc_urls"]:
            jwks = self.get_jwks(oidc_url)
            unverified_header = jwt.get_unverified_header(token)
            token_kid = unverified_header.get("kid")
            if not token_kid:
                raise ValueError("Token header does not contain 'kid'.")

            public_keys = {key["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(key) for key in jwks["keys"]}
            if token_kid in public_keys:
                try:
                    key = public_keys[token_kid]
                    decoded_token = jwt.decode(
                        token,
                        key=key,
                        algorithms=["RS256"],
                        audience=provider["audiences"],
                        options={"verify_exp": True},
                    )
                    self.token_cache[token] = decoded_token
                    return decoded_token
                except jwt.PyJWTError as e:
                    self.logger.error(f"Token validation failed: {e}")
                    raise ValueError("Invalid token.")
        raise ValueError("No matching key found for token.")

    def get_jwks(self, oidc_url: str) -> Dict[str, Union[str, List[Dict[str, str]]]]:
        """
        Fetch and cache JWKS data for a specific OIDC URL.

        :param oidc_url: The OIDC URL.
        :return: JWKS data.
        """
        oidc_config = self.get_oidc_config(oidc_url)
        jwks_uri = oidc_config.get("jwks_uri")
        if not jwks_uri:
            raise ValueError(f"JWKS URI not found for OIDC URL: {oidc_url}")

        if jwks_uri in self.jwks_cache[oidc_url]:
            return self.jwks_cache[oidc_url][jwks_uri]

        response = requests.get(jwks_uri)
        if response.status_code == 200:
            jwks_data = response.json()
            self.jwks_cache[oidc_url][jwks_uri] = jwks_data
            return jwks_data

        response.raise_for_status()
