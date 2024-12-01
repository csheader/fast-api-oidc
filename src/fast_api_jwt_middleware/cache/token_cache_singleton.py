from fast_api_jwt_middleware.cache.cache_protocol_contract import CacheProtocol
from fast_api_jwt_middleware.cache.token_cache import TokenCache
from typing import Any, Optional

class TokenCacheSingleton:
    '''
    A singleton class that provides a global access point to a TokenCache instance.

    This class ensures that only one instance of TokenCache is created and provides methods
    to add, retrieve, remove, and clear tokens from the cache. It is designed to manage
    token caching efficiently with configurable parameters for maximum size and time-to-live.

    Attributes:
        _instance (TokenCache): The singleton instance of the TokenCache.
        _custom_cache (CacheProtocol): A Singleton instance of the provided cache for interactions
    '''
    _instance = None
    _custom_cache: CacheProtocol = None  # Just in case the caller wants to supply their own cache

    @classmethod
    def set_custom_cache(cls, custom_cache: CacheProtocol) -> None:
        '''Set a custom cache instance.'''
        cls._custom_cache = custom_cache

    @classmethod
    def get_instance(cls, maxsize=1000, ttl=300, logger=None):
        '''
        Lazily initialize the singleton instance with the given parameters.

        :param maxsize: Maximum size of the cache.
        :param ttl: Time-to-live for cached tokens in seconds.
        :return: The singleton instance of TokenCache.
        '''
        if cls._custom_cache is not None:
            return cls._custom_cache
        if cls._instance is None:
            cls._instance = TokenCache(maxsize=maxsize, ttl=ttl, logger=logger)
        return cls._instance

    @classmethod
    def add_token(cls, token: str, value: Any) -> None:
        '''Add a token to the cache.'''
        if cls._custom_cache:
            cls._custom_cache.add_token(token, value)
        else:
            cls.get_instance().add_token(token, value)

    @classmethod
    def get_token(cls, token: str) -> Optional[Any]:
        '''Retrieve a token from the cache.'''
        if cls._custom_cache:
            return cls._custom_cache.get_token(token)
        return cls.get_instance().get_token(token)

    @classmethod
    def remove_token(cls, token: str) -> bool:
        '''Remove a token from the cache.'''
        if cls._custom_cache:
            return cls._custom_cache.remove_token(token)
        return cls.get_instance().remove_token(token)

    @classmethod
    def clear(cls) -> None:
        '''Clear all tokens from the cache.'''
        if cls._custom_cache:
            cls._custom_cache.clear()
        else:
            cls.get_instance().clear()

    @classmethod
    def list_tokens(cls, page: int = 1, page_size: int = 10) -> dict:
        '''
        list tokens from the cache, only necessary in debugging scenarios
        '''
        if cls._custom_cache:
            return cls._custom_cache.list_tokens(page, page_size)
        return cls.get_instance().list_tokens(page, page_size)