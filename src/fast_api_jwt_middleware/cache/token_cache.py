import logging
from cachetools import TTLCache
from typing import Any, Optional

# Just in case we somehow get here and a logger wasn't setup.
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class TokenCache:
    '''
    TokenCache handles caching of JWT tokens with a time-to-live (TTL).
    '''
    def __init__(self, maxsize: int = 1000, ttl: int = 300, logger=None) -> None:
        '''
        Initialize the token cache.

        :param maxsize: Maximum size of the cache.
        :param ttl: Time-to-live for cached tokens in seconds.
        '''
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self.logger = logger or logging.getLogger(__name__)

    def _log_token(self, token: str, action: str) -> None:
        '''Log the token action with partial token information.'''
        if len(token) > 60:
            token_info = f'{token[:30]}...{token[-30:]}'  # Log first and last 30 characters
        else:
            token_info = token  # Log the full token if it's shorter than 60 characters
        self.logger.debug(f'{action} token: {token_info}')

    def add_token(self, token: str, value: Any) -> None:
        '''
        Add a token to the cache.

        :param token: The token string.
        :param value: The value to store, typically the decoded token data.
        '''
        self._cache[token] = value
        self._log_token(token, 'Added to cache')

    def get_token(self, token: str) -> Optional[Any]:
        '''
        Retrieve a token from the cache.

        :param token: The token string.
        :return: The cached value or None if not found.
        '''
        value = self._cache.get(token)
        if value is not None:
            self._log_token(token, 'Retrieved cached')
        else:
            self._log_token(token, 'Not found in cache')
        return value

    def remove_token(self, token: str) -> bool:
        '''
        Remove a token from the cache.

        :param token: The token string.
        :return: True if the token was found and removed, False otherwise.
        '''
        if token in self._cache:
            del self._cache[token]
            self._log_token(token, 'Removed from cache')
            return True
        self._log_token(token, 'Not found for removal')
        return False

    def clear(self) -> None:
        '''
        Clear all tokens from the cache.
        '''
        self._cache = TTLCache(maxsize=self._cache.maxsize, ttl=self._cache.ttl)
        self.logger.debug('All tokens cleared from cache.')

    def list_tokens(self, page: int = 1, page_size: int = 10) -> dict:
        '''
        List all tokens in the cache in a pageable fashion.

        :param page: The page number to retrieve (1-based).
        :param page_size: The number of tokens per page.
        :return: A dictionary containing the tokens for the requested page and total count.
        '''
        all_tokens = list(self._cache.items())
        
        # figure out the total number of pages
        total_tokens = len(all_tokens)
        total_pages = (total_tokens + page_size - 1) // page_size
        self.logger.debug(f'Total tokens in cache: {total_tokens}, Total pages: {total_pages}')
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        self.logger.debug(f'Retrieving tokens for page {page}: start index {start_index}, end index {end_index}')
        tokens_page = all_tokens[start_index:end_index]
        result = {
            "total_tokens": total_tokens,
            "total_pages": total_pages,
            "current_page": page,
            "tokens": {
                token: {
                    "value": value,
                    "expiration": self._cache.get(token)
                }
                for token, value in tokens_page
            }
        }
        return result