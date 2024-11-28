import unittest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from src.fast_api_jwt_middleware.middleware import AuthMiddleware, MultiProviderAuthMiddleware

class TestAuthMiddleware(unittest.TestCase):

    def setUp(self):
        """Set up a FastAPI app with AuthMiddleware for testing."""
        self.app = FastAPI()

        # Mock route to test middleware
        @self.app.get("/secure-endpoint")
        async def secure_endpoint(request: Request):
            return {"message": "You have access to this secure endpoint."}

        # Add AuthMiddleware (you may need to adjust parameters based on your implementation)
        self.app.add_middleware(AuthMiddleware, oidc_urls=["https://example.com"], audiences="your-client-id")
        self.client = TestClient(self.app)

    def test_secure_endpoint_access(self):
        """Test accessing a secure endpoint with valid token."""
        # Here you would typically mock the token validation process
        # For example, you might use a valid token in the Authorization header
        response = self.client.get("/secure-endpoint", headers={"Authorization": "Bearer valid_token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "You have access to this secure endpoint."})

    def test_secure_endpoint_access_denied(self):
        """Test accessing a secure endpoint without a valid token."""
        response = self.client.get("/secure-endpoint")
        self.assertEqual(response.status_code, 401)  # Unauthorized

class TestMultiProviderAuthMiddleware(unittest.TestCase):

    def setUp(self):
        """Set up a FastAPI app with MultiProviderAuthMiddleware for testing."""
        self.app = FastAPI()

        # Mock route to test middleware
        @self.app.get("/multi-secure-endpoint")
        async def multi_secure_endpoint(request: Request):
            return {"message": "You have access to this multi-secure endpoint."}

        # Add MultiProviderAuthMiddleware (you may need to adjust parameters based on your implementation)
        self.app.add_middleware(MultiProviderAuthMiddleware, oidc_urls=["https://example.com"], audience=["client-id-1", "client-id-2"])
        self.client = TestClient(self.app)

    def test_multi_secure_endpoint_access(self):
        """Test accessing a secure endpoint with valid token from multiple providers."""
        response = self.client.get("/multi-secure-endpoint", headers={"Authorization": "Bearer valid_token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "You have access to this multi-secure endpoint."})

    def test_multi_secure_endpoint_access_denied(self):
        """Test accessing a secure endpoint without a valid token."""
        response = self.client.get("/multi-secure-endpoint")
        self.assertEqual(response.status_code, 401)  # Unauthorized

if __name__ == "__main__":
    unittest.main()
