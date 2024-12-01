
from fastapi import Request
from fastapi.responses import JSONResponse
import jwt
from starlette.types import ASGIApp
from typing import List, Dict, Union, Optional
from fast_api_oidc.auth.auth_middleware import AuthMiddleware
from fast_api_oidc.cache.cache_protocol_contract import CacheProtocol
from fast_api_oidc.context_holder import request_context
from fast_api_oidc.logger.logger_protocol_contract import LoggerProtocol

class MultiProviderAuthMiddleware(AuthMiddleware):
    '''
    Middleware to handle authentication for multiple OIDC providers.

    This middleware extends the AuthMiddleware to support multiple OpenID Connect (OIDC) providers.
    It determines which provider's configuration to use based on the audience claim in the JWT token.
    The middleware validates the token against the appropriate provider and attaches user information
    to the request state.

    Attributes:
        app (ASGIApp): The FastAPI application instance.
        providers (List[Dict[str, Union[List[str], str]]]): A list of provider configurations, each containing
            OIDC URLs and audiences for validation.
        token_ttl (int): The time-to-live for the token cache, in seconds (default is 300 seconds).
        jwks_ttl (int): The time-to-live for the JWKS cache, in seconds (default is 3600 seconds).
        oidc_ttl (int): The time-to-live for the OIDC configuration cache, in seconds (default is 3600 seconds).
        token_cache_maxsize (int): The maximum size of the token cache (default is 1000).
        logger (Optional[logging.Logger]): A logger instance for logging authentication-related messages. If not provided, a default logger will be used.
        excluded_paths (List[str]): A list of paths to exclude from authentication (default is an empty list).
        roles_key (str): The default claim on the token for authenticating with the providers for your api routes (default is 'roles')
    '''
    def __init__(
        self,
        app: ASGIApp,
        providers: List[Dict[str, Union[List[str], str]]],
        token_ttl: int = 300,
        jwks_ttl: int = 3600,
        oidc_ttl: int = 3600,
        custom_token_cache: Optional[CacheProtocol] = None,
        token_cache_maxsize: int = 1000,
        logger: Optional[LoggerProtocol] = None,
        excluded_paths: List[str] = [],
        roles_key: str = 'roles'
    ) -> None:
        oidc_urls = [
            url
            for provider in providers
            for url in (
                provider['oidc_urls']
                if isinstance(provider['oidc_urls'], list)
                else [provider['oidc_urls']]
            )
        ]
        audiences = [
            audience
            for provider in providers
            for audience in (
                provider['audiences']
                if isinstance(provider['audiences'], list)
                else [provider['audiences']]
            )
        ]
        
        super().__init__(app=app, oidc_urls=oidc_urls, 
                         audiences=audiences, 
                         token_ttl=token_ttl, jwks_ttl=jwks_ttl, oidc_ttl=oidc_ttl,
                         token_cache_maxsize=token_cache_maxsize, logger=logger,
                         excluded_paths=excluded_paths, roles_key=roles_key, custom_token_cache=custom_token_cache)
        self.providers = providers

    def get_provider_for_token(self, token: str) -> Optional[Dict]:
        '''
        Determine which provider's OIDC URLs and audiences match the given token.
        '''
        unverified_claims = jwt.decode(token, options={'verify_signature': False})
        for provider in self.providers:
            if unverified_claims.get('aud') in provider['audiences']:
                return provider
        return None

    async def dispatch(self, request: Request, call_next):
        '''
        Middleware handler to authenticate and attach user info to the request state.
        '''
        token = request.headers.get('Authorization')
        if token:
            token = token.replace('Bearer ', '')
            provider = self.get_provider_for_token(token)
            if provider:
                try:
                    user_data = self.decode_token(token)  # Use the base class method
                    request.state.user = user_data
                    request_context.set(request)
                    return await call_next(request)
                except Exception as e:
                    self.logger.error(f'Authentication failed: {e}')
                    return JSONResponse({'detail': 'Invalid or unauthorized token'}, status_code=401)

        # No token or no matching provider
        request.state.user = None
        return await call_next(request)