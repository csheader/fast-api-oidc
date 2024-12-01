from typing import Any, Optional, Protocol, runtime_checkable, Dict

@runtime_checkable
class CacheProtocol(Protocol):
    """
    CacheProtocol defines a standard interface for token caching operations.

    This protocol outlines the methods that any TokenCache implementation should provide.
    It is designed to ensure that any TokenCache can be used interchangeably in the application,
    as long as it adheres to this interface.
    """

    def add_token(self, token: str, value: Any) -> None:
        """
        Adds a token with its associated value to the cache.

        :param token: The token to be added.
        :param value: The value associated with the token.
        """
        ...

    def get_token(self, token: str) -> Optional[Any]:
        """
        Retrieves the value associated with the given token from the cache.

        :param token: The token to retrieve.
        :return: The value associated with the token, or None if not found.
        """
        ...

    def remove_token(self, token: str) -> bool:
        """
        Removes the specified token from the cache.

        :param token: The token to be removed.
        :return: True if the token was successfully removed, False otherwise.
        """
        ...

    def clear(self) -> None:
        """
        Clears all tokens from the cache.
        """
        ...

    def list_tokens(self, page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        """
        Lists tokens in the cache with pagination.

        :param page: The page number to retrieve.
        :param page_size: The number of tokens per page.
        :return: A dictionary of tokens and their associated values.
        """
        ...