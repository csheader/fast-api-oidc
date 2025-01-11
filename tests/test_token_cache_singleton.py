import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from fast_api_jwt_middleware.cache.token_cache_singleton import TokenCacheSingleton

class TestTokenCacheSingleton(unittest.TestCase):

    def setUp(self):
        """Set up a TokenCacheSingleton instance for testing."""
        self.cache_singleton = TokenCacheSingleton()

    def tearDown(self):
        """Clear the TokenCacheSingleton instance after each test."""
        TokenCacheSingleton.clear()
        TokenCacheSingleton._instance = None
        TokenCacheSingleton._custom_cache = None

    def test_singleton_instance(self):
        """Test that TokenCacheSingleton returns the same instance."""
        another_instance = TokenCacheSingleton()
        self.assertIs(self.cache_singleton.get_instance(), another_instance.get_instance(), "TokenCacheSingleton should be a singleton.")

    def test_add_token(self):
        """Test adding a token to the cache."""
        self.cache_singleton.add_token("token-test-1", {"sub": "user1"})
        self.assertEqual(self.cache_singleton.get_token("token-test-1"), {"sub": "user1"})

    def test_get_token_not_found(self):
        """Test retrieving a token that does not exist."""
        self.assertIsNone(self.cache_singleton.get_token("non_existent_token"))

    def test_remove_token(self):
        """Test removing a token from the cache."""
        self.cache_singleton.add_token("token2", {"user": "test_user_2"})
        self.assertTrue(self.cache_singleton.remove_token("token2"))
        self.assertIsNone(self.cache_singleton.get_token("token2"))

    def test_remove_token_not_found(self):
        """Test removing a token that does not exist."""
        self.assertFalse(self.cache_singleton.remove_token("non_existent_token"))

    def test_remove_all(self):
        self.cache_singleton.add_token("tokenA", {"user": "userA"})
        self.cache_singleton.add_token("tokenB", {"user": "userB"})
        self.cache_singleton.clear()
        should_be_none = self.cache_singleton.get_token("tokenA")
        self.assertIsNone(should_be_none, "Cleared Tokens should no longer exist")
        should_also_be_none = self.cache_singleton.get_token("tokenB")
        self.assertIsNone(should_also_be_none, "Cleared Tokens should no longer exist")

    def test_clear_cache(self):
        """Test clearing the cache."""
        self.cache_singleton.add_token("token3", {"user": "test_user_3"})
        self.cache_singleton.clear()
        self.assertIsNone(self.cache_singleton.get_token("token3"))


if __name__ == "__main__":
    loader = unittest.TestLoader()
    loader.sortTestMethodsUsing = None
    # Order the tests in this file so that they do not impact
    # eachother since this class is a singleton
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestTokenCacheSingleton))
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
