from cachetools import TTLCache
from fastapi import Request
from fastapi.responses import JSONResponse
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError, DecodeError
import logging
import requests
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import List, Dict, Union, Optional
from fast_api_jwt_middleware.logger.logger_protocol_contract import LoggerProtocol
from fast_api_jwt_middleware.cache.cache_protocol_contract import CacheProtocol
from fast_api_jwt_middleware.context_holder import request_context
from fast_api_jwt_middleware.cache.token_cache_singleton import TokenCacheSingleton 

class AuthMiddleware(BaseHTTPMiddleware):
    '''
    Middleware for handling authentication with a single OpenID Connect (OIDC) provider.

    This middleware manages authentication by validating JWT tokens against a specified 
    OIDC provider. It supports multiple OIDC URLs and utilizes caching mechanisms to optimize 
    performance and reduce the number of network requests.

    Attributes:
        app (ASGIApp): The FastAPI application instance that this middleware is applied to.
        oidc_urls (List[str]): A list of well-known OIDC URLs for the identity provider (IDP).
        audiences (List[str]): A list of audiences that the tokens must be validated against.
        token_cache (TTLCache): A cache for storing validated tokens to reduce validation overhead.
        jwks_cache (Dict[str, TTLCache]): A cache for storing JSON Web Key Sets (JWKS) data for each OIDC URL.
        oidc_config_cache (TTLCache): A cache for storing OIDC configuration data to minimize network requests.
        logger (logging.Logger): A logger instance for logging authentication-related messages. If not provided, a default logger will be used.
        excluded_paths (List[str]): A list of paths that should be excluded from authentication checks (default is an empty list).
        supported_algorithms (Dict[str, List[str]]): A dictionary mapping OIDC URLs to their supported signing algorithms.
    '''
    def __init__(
        self,
        app: ASGIApp,
        oidc_urls: List[str],
        audiences: List[str],
        token_ttl: int = 300,
        jwks_ttl: int = 3600,
        oidc_ttl: int = 3600,
        custom_token_cache: Optional[CacheProtocol] = None,
        token_cache_maxsize: int = 1000,
        logger: Optional[LoggerProtocol] = None,
        excluded_paths: List[str] = [],
        roles_key: str = 'roles'
    ) -> None:
        '''
        Initializes the AuthMiddleware for handling authentication with a single OIDC provider.

        :param app: The FastAPI application instance that this middleware will be applied to.
        :param oidc_urls: A list of well-known OIDC URLs for the identity provider (IDP).
        :param audiences: A list of audiences that the tokens must be validated against.
        :param token_ttl: The time-to-live for the token cache, in seconds (default is 300 seconds).
        :param jwks_ttl: The time-to-live for the JWKS cache, in seconds (default is 3600 seconds).
        :param oidc_ttl: The time-to-live for the OIDC configuration cache, in seconds (default is 3600 seconds).
        :param token_cache_maxsize: The maximum size of the token cache (default is 1000).
        :param logger: An optional logger instance for logging authentication-related messages. If not provided, a default logger will be used.
        :param excluded_paths: A list of paths that should be excluded from authentication checks (default is an empty list).
        :param roles_key: The default location for your roles within your authentication context. (default is 'roles')
        :raises ValueError: If no OIDC Url or Audience is provided a Value Error is thrown to notify the caller
        :raises TypeError: If the LoggerProtocol is not implemented on your logger a typeerror will be thrown
        '''
        super().__init__(app)
        # An OIDC url is required to run this middleware. If there is not
        # at least one OIDC url, we should throw an error.
        if not oidc_urls or not isinstance(oidc_urls, list) or not all(oidc_urls):
            raise ValueError("Parameter 'oidc_urls' must be a non-empty list of OIDC URLs.")
        
        # We do not want to allow authentication without a provided audience.
        # Throw a value error if no audience was provided.
        if not audiences or not isinstance(audiences, list) or not all(audiences):
            raise ValueError("Parameter 'audiences' must be a non-empty list of audience strings.")
        if logger is None:
            print('No logger has been provided to the OIDC Middleware. It is recommended that you provider a logger instance to the middleware. Using default logger.')
            self.logger = logging.getLogger(__name__)
        else:
            if not isinstance(logger, LoggerProtocol):
                raise TypeError("Logger must implement the logging protocol.")
            self.logger = logger
        self.oidc_urls: List[str] = oidc_urls
        self.audiences: List[str] = audiences
        self.excluded_paths = excluded_paths
        self.roles_key = roles_key
        if custom_token_cache is not None:
            TokenCacheSingleton.set_custom_cache(custom_token_cache)
        self.token_cache = TokenCacheSingleton.get_instance(
            maxsize=token_cache_maxsize,
            ttl=token_ttl,
            logger=self.logger
        )
        self.jwks_cache: Dict[str, TTLCache] = {
            oidc_url: TTLCache(maxsize=10, ttl=jwks_ttl) for oidc_url in oidc_urls
        }
        self.oidc_config_cache: TTLCache = TTLCache(maxsize=len(oidc_urls), ttl=oidc_ttl)
        self.supported_algorithms: Dict[str, List[str]] = self.get_supported_algorithms()

    def get_oidc_config(self, oidc_url: str) -> Dict[str, Union[str, List[str]]]:
        '''
        Fetches and caches OIDC configuration data.

        :param oidc_url: The well-known OIDC URL.
        :return: OIDC configuration data.
        '''
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
        '''
        Fetches supported signing algorithms for each OIDC URL.

        :return: Dictionary of OIDC URLs and their supported algorithms.
        '''
        supported_algorithms = {}
        for oidc_url in self.oidc_urls:
            oidc_config = self.get_oidc_config(oidc_url)
            supported_algorithms[oidc_url] = oidc_config.get('id_token_signing_alg_values_supported', ['RS256'])
        return supported_algorithms

    def get_jwks(self, oidc_url: str, oidc_config: Dict[str, Union[str, List[str]]]) -> Dict[str, Union[str, List[Dict[str, str]]]]:
        '''
        Fetches and caches JSON Web Key Sets (JWKS) data for the specified OIDC URL.

        This method retrieves the JWKS from the OIDC provider's configuration and caches it
        for future use. The JWKS contains the public keys used to verify the signatures of
        JWT tokens issued by the OIDC provider.

        :param oidc_url: The well-known OIDC URL from which to fetch the JWKS.
        :param oidc_config: The OIDC configuration data containing the JWKS URI.
        :return: JWKS data as a dictionary, which includes the keys used for token verification.
        :raises ValueError: If the JWKS URI is not found in the OIDC configuration.
        '''
        jwks_uri = oidc_config.get('jwks_uri')
        if not jwks_uri:
            raise ValueError(f'JWKS URI not found for OIDC URL: {oidc_url}')

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
        '''
        Decode and validate a JWT token based on the 'kid' in its header.

        This method checks if the provided token is valid by verifying its signature against
        the public keys obtained from the OIDC provider's JWKS. If the token is valid, it
        caches the decoded token for future use to optimize performance.

        :param token: The JWT token to decode and validate.
        :return: A dictionary containing the decoded token data, including claims.
        :raises InvalidTokenError: If the token is invalid or cannot be decoded.
        :raises ExpiredSignatureError: If the token has expired.
        '''
        if not token:
            raise InvalidTokenError('No token provided.')

        # If the token is cached, then we can assume the token has been
        # validated within the the cache lifetime provided in the constructor
        cached_token = self.token_cache.get_token(token)
        if cached_token:
            self.logger.debug('Token found in cache')
            return cached_token
        # Attempt to validate the token
        try:
            unverified_header = jwt.get_unverified_header(token)
            token_kid = unverified_header.get('kid')
            if not token_kid:
                raise InvalidTokenError("Token header does not contain 'kid'.")

            for oidc_url in self.oidc_urls:
                oidc_config = self.get_oidc_config(oidc_url)
                issuer = oidc_config['issuer']
                jwks = self.get_jwks(oidc_url, oidc_config)
                public_keys = {key['kid']: jwt.PyJWK(key) for key in jwks['keys']}
                if token_kid in public_keys:
                    try:
                        key = public_keys[token_kid]
                        decoded_token = jwt.decode(
                            token,
                            key=key,
                            issuer=issuer,
                            algorithms=self.supported_algorithms[oidc_url],
                            audience=self.audiences,
                            options={'verify_exp': True, 'verify_iss':True, 'verify_aud': True}
                        )
                        self.logger.debug('Token valid, caching token for future use.')
                        self.token_cache.add_token(token, decoded_token)
                        return decoded_token
                    except ExpiredSignatureError as e:
                        raise ExpiredSignatureError('Token has expired.')
                    except InvalidTokenError as e:
                        raise InvalidTokenError(f'Token is invalid. {str(e)}')
        except DecodeError:
            self.logger.error('Error decoding token.')
            raise InvalidTokenError('An error occurred while decoding the token.')

        raise InvalidTokenError('Invalid token: Key not found.')

    async def dispatch(self, request: Request, call_next) -> JSONResponse:
        '''
        Middleware handler to authenticate requests and attach user information to the request state.

        This method checks for the presence of a JWT token in the Authorization header of the request.
        If a valid token is found, it decodes the token and attaches the user data to the request state.
        If the token is missing or invalid, it returns an appropriate JSON response indicating the error.

        :param request: The incoming HTTP request.
        :param call_next: A function to call the next middleware or endpoint in the request processing chain.
        :return: A JSONResponse containing the result of the request processing.
        '''
        if request.url.path in self.excluded_paths:
            return await call_next(request)
        token = request.headers.get('Authorization')
        if not token:
            return JSONResponse(status_code=401, content={'detail': 'No token provided.'})
        token = token.replace('Bearer ', '')
        try:
            user_data = self.decode_token(token)
            request.state.user = user_data
            request_context.set(request)
            return await call_next(request)
        except ExpiredSignatureError:
            return JSONResponse(status_code=401, content={'detail': 'Token has expired. Please log in again.'})
        except InvalidTokenError as e:
            self.logger.error(f'Invalid token error: {str(e)}')
            return JSONResponse(status_code=401, content={'detail': str(e)})
        except Exception as e:
            self.logger.error(f'Authentication error: {str(e)}')
            return JSONResponse(status_code=500, content={'detail': 'An error occurred during authentication. Please try again.'})

