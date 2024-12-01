
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
from tests import test_auth_middleware
from tests import test_multi_provider_auth_middleware
from tests import test_oidc_helper
from tests import test_oidc_providers
from tests import test_wrapper
from tests import test_token_cache
from tests import test_token_cache_singleton

loader = unittest.TestLoader()
suite = unittest.TestSuite()

# Order the tests so that the cache_singleton tests happen
# without impacting the token_cache tests. 
suite.addTests(loader.loadTestsFromModule(test_token_cache_singleton))
suite.addTests(loader.loadTestsFromModule(test_auth_middleware))
suite.addTests(loader.loadTestsFromModule(test_multi_provider_auth_middleware))
suite.addTests(loader.loadTestsFromModule(test_oidc_helper))
suite.addTests(loader.loadTestsFromModule(test_oidc_providers))
suite.addTests(loader.loadTestsFromModule(test_wrapper))
suite.addTests(loader.loadTestsFromModule(test_token_cache))

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)