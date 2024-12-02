import unittest
from unittest.mock import patch, Mock, MagicMock
from unittest import IsolatedAsyncioTestCase
from fastapi import Request
from fastapi.responses import JSONResponse
from jwt import InvalidTokenError

# Import the MultiProviderAuthMiddleware from the src directory
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fast_api_jwt_middleware.auth.multi_provider_auth_middleware import MultiProviderAuthMiddleware
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

class TestMultiProviderAuthMiddleware(IsolatedAsyncioTestCase):

    @patch('fast_api_jwt_middleware.auth.auth_middleware.requests.get')
    def setUp(self, mock_requests_get):
        # Mock the response of requests.get during instantiation
        def mocked_requests_get(url, *args, **kwargs):
            if url == 'https://provider1.com/.well-known/openid-configuration':
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    'issuer': 'https://provider1.com',
                    'jwks_uri': 'https://provider1.com/jwks',
                    'id_token_signing_alg_values_supported': ['RS256']
                }
                return mock_response
            elif url == 'https://provider2.com/.well-known/openid-configuration':
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    'issuer': 'https://provider2.com',
                    'jwks_uri': 'https://provider2.com/jwks',
                    'id_token_signing_alg_values_supported': ['RS256']
                }
                return mock_response
            else:
                raise ValueError(f'Unhandled URL: {url}')
        mock_requests_get.side_effect = mocked_requests_get

        # Set up the MultiProviderAuthMiddleware instance
        self.app = MagicMock()
        self.providers = [
            {
                'oidc_urls': 'https://provider1.com/.well-known/openid-configuration',
                'audiences': ['audience1'],
                'roles_key': 'roles'
            },
            {
                'oidc_urls': 'https://provider2.com/.well-known/openid-configuration',
                'audiences': ['audience2'],
                'roles_key': 'permissions'
            }
        ]
        self.logger = MockLogger()
        self.middleware = MultiProviderAuthMiddleware(
            app=self.app,
            providers=self.providers,
            logger=self.logger
        )

        # Clear caches to ensure fresh state for each test
        self.middleware.oidc_config_cache.clear()
        self.middleware.jwks_cache.clear()

    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.jwt.decode')
    def test_get_provider_for_token(self, mock_jwt_decode):
        """
        Test get_provider_for_token method to ensure it selects the correct provider based on token audience.
        """
        token = 'dummy_token'

        # Mock jwt.decode to return unverified claims
        mock_jwt_decode.return_value = {'aud': 'audience1'}

        provider = self.middleware.get_provider_for_token(token)

        self.assertIsNotNone(provider)
        self.assertEqual(provider['audiences'], ['audience1'])

        # Test with a different audience
        mock_jwt_decode.return_value = {'aud': 'audience2'}

        provider = self.middleware.get_provider_for_token(token)

        self.assertIsNotNone(provider)
        self.assertEqual(provider['audiences'], ['audience2'])

        # Test with an audience that doesn't match any provider
        mock_jwt_decode.return_value = {'aud': 'unknown_audience'}

        provider = self.middleware.get_provider_for_token(token)

        self.assertIsNone(provider)

    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.jwt.decode')
    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.MultiProviderAuthMiddleware.decode_token')
    async def test_dispatch_with_valid_token(self, mock_decode_token, mock_jwt_decode_unverified):
        """
        Test dispatch method with a valid token.
        """
        # Mock jwt.decode to return unverified claims
        mock_jwt_decode_unverified.return_value = {'aud': 'audience1'}

        # Mock decode_token to return user data
        mock_user_data = {'sub': 'user1', 'roles': ['admin']}
        mock_decode_token.return_value = mock_user_data

        # Mock request with Authorization header
        headers = [(b'authorization', b'Bearer valid_token')]
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/somepath',
            'headers': headers
        }
        receive = MagicMock()
        request = Request(scope, receive)

        # Mock call_next
        async def call_next(request):
            return JSONResponse({'message': 'Success'}, status_code=200)

        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body.decode(), '{"message":"Success"}')
        # Verify that decode_token was called with the correct token
        mock_decode_token.assert_called_with('valid_token')
        # Ensure user data is attached to request.state
        self.assertIsNotNone(request.state.user)
        self.assertEqual(request.state.user['sub'], mock_user_data['sub'], 'The sub on the token should match what was provided from the mock response \'user1\'')
        self.assertEqual(request.state.user['roles'], mock_user_data['roles'], 'The roles property should be an array of length 1 with \'admin\'')

    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.jwt.decode')
    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.MultiProviderAuthMiddleware.decode_token')
    async def test_dispatch_with_invalid_token(self, mock_decode_token, mock_jwt_decode_unverified):
        """
        Test dispatch method with an invalid token.
        """
        # Mock jwt.decode to return unverified claims
        mock_jwt_decode_unverified.return_value = {'aud': 'audience1'}

        # Mock decode_token to raise an exception
        mock_decode_token.side_effect = InvalidTokenError('Invalid token')

        # Mock request with Authorization header
        headers = [(b'authorization', b'Bearer invalid_token')]
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/somepath',
            'headers': headers
        }
        receive = MagicMock()
        request = Request(scope, receive)

        # Mock call_next
        async def call_next(request):
            return JSONResponse({'message': 'Success'}, status_code=200)

        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 401)
        self.assertIn('Invalid token', response.body.decode())

    async def test_dispatch_no_token(self):
        """
        Test dispatch method when no Authorization header is provided.
        """
        # Mock request without Authorization header
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/somepath',
            'headers': []
        }
        receive = MagicMock()
        request = Request(scope, receive)

        # Mock call_next
        async def call_next(request):
            return JSONResponse({'message': 'No Token'}, status_code=200)

        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.body.decode(), '{"detail":"No token provided."}')

    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.jwt.decode')
    async def test_dispatch_no_matching_provider(self, mock_jwt_decode_unverified):
        """
        Test dispatch method when token's audience doesn't match any provider.
        """
        # Mock jwt.decode to return unverified claims with unknown audience
        mock_jwt_decode_unverified.return_value = {'aud': 'unknown_audience'}

        # Mock request with Authorization header
        headers = [(b'authorization', b'Bearer token_with_unknown_audience')]
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/somepath',
            'headers': headers
        }
        receive = MagicMock()
        request = Request(scope, receive)

        # Mock call_next
        async def call_next(request):
            return JSONResponse({'message': 'No Matching Provider'}, status_code=200)

        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.body.decode(), '{"detail":"The provided token is invalid for this service"}')

    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.jwt.decode')
    @patch('fast_api_jwt_middleware.auth.multi_provider_auth_middleware.MultiProviderAuthMiddleware.decode_token')
    async def test_dispatch_with_exception_in_decode(self, mock_decode_token, mock_jwt_decode_unverified):
        """
        Test dispatch method when an exception occurs in decode_token.
        """
        # Mock jwt.decode to return unverified claims
        mock_jwt_decode_unverified.return_value = {'aud': 'audience1'}

        # Mock decode_token to raise an exception
        mock_decode_token.side_effect = Exception('Some error')

        # Mock request with Authorization header
        headers = [(b'authorization', b'Bearer token_causing_exception')]
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/somepath',
            'headers': headers
        }
        receive = MagicMock()
        request = Request(scope, receive)

        # Mock call_next
        async def call_next(request):
            return JSONResponse({'message': 'Should not reach here'}, status_code=200)

        response = await self.middleware.dispatch(request, call_next)

        self.assertEqual(response.status_code, 500)
        self.assertIn('An error occurred during authentication. Please try again.', response.body.decode())

if __name__ == '__main__':
    unittest.main()
