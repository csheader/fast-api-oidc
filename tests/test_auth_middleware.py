import unittest
from unittest.mock import patch, Mock, MagicMock
from unittest import IsolatedAsyncioTestCase
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.types import Scope, Receive, Send
import logging
from jwt import InvalidTokenError

# Import the AuthMiddleware from the src directory
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fast_api_jwt_middleware.auth.auth_middleware import AuthMiddleware
from fast_api_jwt_middleware.logger.logger_protocol_contract import LoggerProtocol

# Mock logger that implements LoggerProtocol
class MockLogger(LoggerProtocol):
    def debug(self, msg: str, *args, **kwargs) -> None:
        pass
    def info(self, msg: str, *args, **kwargs) -> None:
        pass
    def warning(self, msg: str, *args, **kwargs) -> None:
        pass
    def error(self, msg: str, *args, **kwargs) -> None:
        pass
    def critical(self, msg: str, *args, **kwargs) -> None:
        pass

class TestAuthMiddleware(IsolatedAsyncioTestCase):

    @patch('fast_api_jwt_middleware.auth.auth_middleware.requests.get')
    def setUp(self, mock_requests_get):
        # Mock the response of requests.get during instantiation
        mock_oidc_config_response = Mock()
        mock_oidc_config_response.status_code = 200
        mock_oidc_config_response.json.return_value = {
            'issuer': 'https://example.com',
            'jwks_uri': 'https://example.com/jwks',
            'id_token_signing_alg_values_supported': ['RS256']
        }
        mock_requests_get.return_value = mock_oidc_config_response

        # Set up the AuthMiddleware instance
        self.app = MagicMock()
        self.oidc_urls = ['https://example.com/.well-known/openid-configuration']
        self.audiences = ['your-audience']
        self.logger = MockLogger()
        self.middleware = AuthMiddleware(
            app=self.app,
            oidc_urls=self.oidc_urls,
            audiences=self.audiences,
            logger=self.logger
        )

    @patch('fast_api_jwt_middleware.auth.auth_middleware.requests.get')
    def test_get_oidc_config(self, mock_get):
        """
        Test get_oidc_config method to ensure it fetches and caches OIDC configuration.
        """
        # Mock the response of requests.get
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'issuer': 'https://example.com',
            'jwks_uri': 'https://example.com/jwks',
            'id_token_signing_alg_values_supported': ['RS256']
        }
        mock_get.return_value = mock_response
        oidc_config = self.middleware.get_oidc_config(self.oidc_urls[0])

        self.assertEqual(oidc_config['issuer'], 'https://example.com')
        self.assertEqual(oidc_config['jwks_uri'], 'https://example.com/jwks')
        # Ensure that the result is cached
        self.assertIn(self.oidc_urls[0], self.middleware.oidc_config_cache)

    @patch('fast_api_jwt_middleware.auth.auth_middleware.requests.get')
    def test_get_jwks(self, mock_get):
        """
        Test get_jwks method to ensure it fetches and caches JWKS data.
        """
        # Mock OIDC config
        oidc_config = {'jwks_uri': 'https://example.com/jwks'}
        # Mock the response of requests.get
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'keys': [{'kid': 'key1', 'kty': 'RSA'}]}
        mock_get.return_value = mock_response
        jwks = self.middleware.get_jwks(self.oidc_urls[0], oidc_config)

        self.assertIn('keys', jwks)
        self.assertEqual(jwks['keys'][0]['kid'], 'key1')

        # Ensure that the result is cached
        self.assertIn('https://example.com/jwks', self.middleware.jwks_cache[self.oidc_urls[0]])
        # Verify that requests.get was called once
        mock_get.assert_called_once_with('https://example.com/jwks')

    @patch('fast_api_jwt_middleware.auth.auth_middleware.jwt.PyJWK')
    @patch('fast_api_jwt_middleware.auth.auth_middleware.jwt.decode')
    @patch('fast_api_jwt_middleware.auth.auth_middleware.jwt.get_unverified_header')
    @patch('fast_api_jwt_middleware.auth.auth_middleware.requests.get')
    def test_decode_token(self, mock_requests_get, mock_get_unverified_header, mock_jwt_decode, mock_PyJWK):
        """
        Test decode_token method to ensure it decodes and validates JWT tokens.
        """
        # Mock token cache
        self.middleware.token_cache.get_token = MagicMock(return_value=None)
        self.middleware.token_cache.add_token = MagicMock()

        # Mock unverified header
        mock_get_unverified_header.return_value = {'kid': 'key1'}

        # Mock OIDC config response
        mock_oidc_config_response = Mock()
        mock_oidc_config_response.status_code = 200
        mock_oidc_config_response.json.return_value = {
            'issuer': 'https://example.com',
            'jwks_uri': 'https://example.com/jwks',
            'id_token_signing_alg_values_supported': ['RS256']
        }

        # Mock JWKS response
        mock_jwks_response = Mock()
        mock_jwks_response.status_code = 200
        mock_jwks_response.json.return_value = {'keys': [{'kid': 'key1', 'kty': 'RSA', 'n': '...', 'e': '...'}]}

        # Set side effects for requests.get to return OIDC config and then JWKS
        mock_requests_get.side_effect = lambda url: (
            mock_oidc_config_response if 'oidc_config_url' in url else mock_jwks_response
        )
        # Intercept pyjwk, I'm sure those guys test their own stuff, we don't need to do it too
        mock_key_instance = MagicMock()
        mock_PyJWK.return_value = mock_key_instance
        # make a fake user
        mock_jwt_decode.return_value = {'sub': 'user1'}

        token = 'dummy_token'

        decoded_token = self.middleware.decode_token(token)

        self.assertEqual(decoded_token, {'sub': 'user1'})
        self.middleware.token_cache.add_token.assert_called_with(token, {'sub': 'user1'})
        # Ensure jwt.decode was called with correct parameters
        mock_jwt_decode.assert_called_with(
            token,
            key=mock_key_instance,
            issuer='https://example.com',
            algorithms=['RS256'],
            audience=self.audiences,
            options={'verify_exp': True, 'verify_iss':True, 'verify_aud': True}
        )
    async def test_dispatch_no_token(self):
        """
        Test dispatch method when no Authorization header is provided.
        """
        # do not provide the token, we want to make sure we get a 401
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/',
            'headers': []
        }
        receive = MagicMock()
        request = Request(scope, receive)
        async def call_next(request):
            return JSONResponse({'message': 'Success'}, status_code=200)
        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 401)
        self.assertIn('No token provided', response.body.decode())

    @patch('fast_api_jwt_middleware.auth.auth_middleware.AuthMiddleware.decode_token')
    async def test_dispatch_valid_token(self, mock_decode_token):
        """
        Test dispatch method with a valid token.
        """
        # return a user with the call and mock a token
        mock_decode_token.return_value = {'sub': 'user1'}
        headers = [(b'authorization', b'Bearer dummy_token')]
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/',
            'headers': headers
        }
        receive = MagicMock()
        request = Request(scope, receive)
        async def call_next(request):
            return JSONResponse({'message': 'Success'}, status_code=200)
        response = await self.middleware.dispatch(request, call_next)
        self.assertEqual(response.status_code, 200, 'The return status for a valid token should be 200')
        self.assertEqual(response.body.decode(), '{"message":"Success"}', 'The expected response for this call does not match the expectation')
        mock_decode_token.assert_called_with('dummy_token')
        # Ensure user data is attached to request.state
        self.assertEqual(request.state.user, {'sub': 'user1'}, 'The method should have been called with our fake user.')

    @patch('fast_api_jwt_middleware.auth.auth_middleware.AuthMiddleware.decode_token')
    async def test_dispatch_invalid_token(self, mock_decode_token):
        """
        Test dispatch method when decode_token raises an InvalidTokenError.
        """
        # throw an invalid token error to validate error handling
        mock_decode_token.side_effect = InvalidTokenError('Invalid token')
        # create mock data for the request
        headers = [(b'authorization', b'Bearer invalid_token')]
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/',
            'headers': headers
        }
        receive = MagicMock()
        request = Request(scope, receive)
        async def call_next(request):
            return JSONResponse({'message': 'Success'}, status_code=200)
        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 401, 'In the case of an invalid token, a 401 should be the response.')
        self.assertIn('Invalid token', response.body.decode(), 'The expected response for an invalid token should be \'Invalid token\'')
        mock_decode_token.assert_called_with('invalid_token')

    def test_init_logger_none(self):
        """
        Test that default logger is used when none is provided.
        """
        # Mock all the things.
        with patch('fast_api_jwt_middleware.auth.auth_middleware.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'issuer': 'https://example.com',
                'jwks_uri': 'https://example.com/jwks',
                'id_token_signing_alg_values_supported': ['RS256']
            }
            mock_get.return_value = mock_response

            middleware = AuthMiddleware(
                app=self.app,
                oidc_urls=self.oidc_urls,
                audiences=self.audiences
            )
            self.assertIsInstance(middleware.logger, logging.Logger)

    def test_init_logger_invalid(self):
        """
        Test that TypeError is raised when invalid logger is provided.
        """
        with self.assertRaises(TypeError):
            AuthMiddleware(
                app=self.app,
                oidc_urls=self.oidc_urls,
                audiences=self.audiences,
                logger='invalid_logger'
            )

    @patch('fast_api_jwt_middleware.auth.auth_middleware.requests.get')
    def test_get_oidc_config_cache(self, mock_get):
        """
        Test that get_oidc_config uses the cache after the first call.
        """
        # First call should fetch from network
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'issuer': 'https://example.com', 'jwks_uri': 'https://example.com/jwks'}
        mock_get.return_value = mock_response

        oidc_config_first = self.middleware.get_oidc_config(self.oidc_urls[0])
        self.assertEqual(oidc_config_first['issuer'], 'https://example.com')

        # Second call should use cache, so requests.get should not be called again
        mock_get.reset_mock()
        oidc_config_second = self.middleware.get_oidc_config(self.oidc_urls[0])
        self.assertEqual(oidc_config_second['issuer'], 'https://example.com')
        mock_get.assert_not_called()

    @patch('fast_api_jwt_middleware.auth.auth_middleware.jwt.get_unverified_header')
    def test_decode_token_cached(self, mock_get_unverified_header):
        """
        Test that decode_token uses the cache if the token is already cached.
        """
        # Mock token cache to return a cached token
        cached_token_data = {'sub': 'user1'}
        self.middleware.token_cache.get_token = MagicMock(return_value=cached_token_data)

        token = 'dummy_token'
        decoded_token = self.middleware.decode_token(token)

        self.assertEqual(decoded_token, cached_token_data)
        # Ensure that get_unverified_header was not called since token was cached
        mock_get_unverified_header.assert_not_called()

    async def test_dispatch_excluded_path(self):
        """
        Test dispatch method for a path that is in excluded_paths.
        """
        self.middleware.excluded_paths = ['/excluded']
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/excluded',
            'headers': []
        }
        receive = MagicMock()
        request = Request(scope, receive)
        async def call_next(request):
            return JSONResponse({'message': 'Excluded'}, status_code=200)
        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 200, 'The path should be excluded from authentication and should respond with a 200.')
        self.assertEqual(response.body.decode(), '{"message":"Excluded"}', 'The body should be what we setup in the mock.')

if __name__ == '__main__':
    unittest.main()
