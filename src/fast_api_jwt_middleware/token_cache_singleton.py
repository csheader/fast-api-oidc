from fast_api_jwt_middleware.token_cache import TokenCache
from typing import Any, Optional

class TokenCacheSingleton:
    '''
    A singleton class that provides a global access point to a TokenCache instance.

    This class ensures that only one instance of TokenCache is created and provides methods
    to add, retrieve, remove, and clear tokens from the cache. It is designed to manage
    token caching efficiently with configurable parameters for maximum size and time-to-live.

    Attributes:
        _instance (TokenCache): The singleton instance of the TokenCache.
    '''
    _instance = None

    @classmethod
    def get_instance(cls, maxsize=1000, ttl=300, logger=None):
        '''
        Lazily initialize the singleton instance with the given parameters.

        :param maxsize: Maximum size of the cache.
        :param ttl: Time-to-live for cached tokens in seconds.
        :return: The singleton instance of TokenCache.
        '''
        if cls._instance is None:
            cls._instance = TokenCache(maxsize=maxsize, ttl=ttl, logger=logger)
        return cls._instance

    @classmethod
    def add_token(cls, token: str, value: Any) -> None:
        '''Add a token to the cache.'''
        cls.get_instance().add_token(token, value)

    @classmethod
    def get_token(cls, token: str) -> Optional[Any]:
        '''Retrieve a token from the cache.'''
        return cls.get_instance().get_token(token)

    @classmethod
    def remove_token(cls, token: str) -> bool:
        '''Remove a token from the cache.'''
        return cls.get_instance().remove_token(token)

    @classmethod
    def clear(cls) -> None:
        '''Clear all tokens from the cache.'''
        cls.get_instance().clear()