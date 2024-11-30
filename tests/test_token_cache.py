import unittest
from time import sleep
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fast_api_jwt_middleware.cache.token_cache import TokenCache

class TestTokenCache(unittest.TestCase):

    def setUp(self):
        """Set up a TokenCache instance for testing."""
        self.cache = TokenCache(maxsize=5, ttl=2)  # Small cache for testing

    def test_add_token(self):
        """Test adding a token to the cache."""
        self.cache.add_token("token1", {"user": "test_user"})
        self.assertEqual(self.cache.get_token("token1"), {"user": "test_user"})

    def test_get_token_not_found(self):
        """Test retrieving a token that does not exist."""
        self.assertIsNone(self.cache.get_token("non_existent_token"))

    def test_remove_token(self):
        """Test removing a token from the cache."""
        self.cache.add_token("token2", {"user": "test_user_2"})
        self.assertTrue(self.cache.remove_token("token2"))
        self.assertIsNone(self.cache.get_token("token2"))

    def test_remove_token_not_found(self):
        """Test removing a token that does not exist."""
        self.assertFalse(self.cache.remove_token("non_existent_token"))

    def test_clear_cache(self):
        """Test clearing the cache."""
        self.cache.add_token("token3", {"user": "test_user_3"})
        self.cache.clear()
        self.assertIsNone(self.cache.get_token("token3"))

    def test_ttl_expiration(self):
        """Test that tokens expire after the TTL."""
        self.cache.add_token("token4", {"user": "test_user_4"})
        sleep(3)  # Wait for the token to expire
        self.assertIsNone(self.cache.get_token("token4"))

    def test_cache_size_limit(self):
        """Test that the cache respects the maximum size limit."""
        for i in range(6):  # Add 6 tokens
            self.cache.add_token(f"token{i}", {"user": f"user_{i}"})
        self.assertIsNone(self.cache.get_token("token0"))  # The first token should be evicted

    def test_list_tokens(self):
        """Test listing tokens with pagination."""
        # Add tokens to the cache
        self.cache.add_token("token1", {"user": "user1"})
        self.cache.add_token("token2", {"user": "user2"})
        self.cache.add_token("token3", {"user": "user3"})

        # List tokens with pagination
        page = 1
        page_size = 2
        tokens_page = self.cache.list_tokens(page=page, page_size=page_size)

        # Check the total tokens and the current page
        self.assertEqual(tokens_page["total_tokens"], 3)
        self.assertEqual(tokens_page["total_pages"], 2)
        self.assertEqual(tokens_page["current_page"], 1)

        # Check the tokens returned
        expected_tokens = {
            "token1": {
                "value": {"user": "user1"},
                "expiration": self.cache.get_token("token1")  # This will return the value, including expiration
            },
            "token2": {
                "value": {"user": "user2"},
                "expiration": self.cache.get_token("token2")
            }
        }
        self.assertEqual(tokens_page["tokens"], expected_tokens)

if __name__ == "__main__":
    unittest.main()