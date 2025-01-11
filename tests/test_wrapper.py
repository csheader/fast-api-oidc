import asyncio
import unittest
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from fast_api_jwt_middleware.utils import secure_route, do_role_check, is_called_from_async_context

def mock_get_current_user():
    return {"username": "test_user", "roles": ["admin"]}

def sync_function(x):
    return x * 2

async def async_function(x):
    await asyncio.sleep(0.1)
    return x * 2

class TestSecureRoute(unittest.TestCase):

    def setUp(self):
        """Set up a FastAPI app for testing."""
        self.app = FastAPI()
        self.app.state.mock_user = {"username": "test_user", "roles": ["admin"]}
        @self.app.middleware("http")
        async def set_user_middleware(request: Request, call_next):
            request.state.user = self.app.state.mock_user
            response = await call_next(request)
            return response
        
        self.app.state.mock_user = {"username": "test_user", "roles": ["admin"]}

        # Add a route with the secure_route decorator
        @self.app.get("/secure-endpoint")
        @secure_route(required_roles="admin")
        async def secure_endpoint(request: Request, user: dict = Depends(mock_get_current_user)):
            return {"message": "You have access to this secure endpoint."}

        self.client = TestClient(self.app)

    def test_secure_endpoint_access(self):
        """Test accessing a secure endpoint with the correct role."""
        response = self.client.get("/secure-endpoint")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "You have access to this secure endpoint."})

    def test_secure_endpoint_access_denied(self):
        """Test accessing a secure endpoint without the required role."""
        # Modify the mock to simulate a user without the required role
        self.app.state.mock_user = {"username": "test_user", "roles": []}
        response = self.client.get("/secure-endpoint")
        self.assertEqual(response.status_code, 403)  # Forbidden
        self.assertIn("detail", response.json())

    def test_secure_endpoint_no_user(self):
        """Test accessing a secure endpoint without a user."""
        self.app.state.mock_user = None
        response = self.client.get("/secure-endpoint")
        self.assertEqual(response.status_code, 401)  # Unauthorized
        self.assertIn("detail", response.json())

    def test_do_role_check_with_valid_role(self):
        """Test do_role_check with a user having a valid role."""
        user = {"roles": ["admin", "user"]}
        required_roles = ["admin", "editor"]
        try:
            do_role_check(user, required_roles, roles_key='roles')
        except HTTPException as e:
            self.fail(f"do_role_check raised HTTPException unexpectedly: {e}")

    def test_do_role_check_with_invalid_role(self):
        """Test do_role_check with a user not having the required roles."""
        user = {"roles": ["user"]}
        required_roles = ["admin", "editor"]
        with self.assertRaises(HTTPException) as context:
            do_role_check(user, required_roles, roles_key='roles')
        self.assertEqual(context.exception.status_code, 403)
        self.assertIn("You do not have the required role(s)", context.exception.detail)

    def test_do_role_check_with_empty_roles(self):
        """Test do_role_check with an empty user roles list."""
        user = {"roles": []}
        required_roles = ["admin", "editor"]
        with self.assertRaises(HTTPException) as context:
            do_role_check(user, required_roles, roles_key='roles')
        self.assertEqual(context.exception.status_code, 403)
        self.assertIn("You do not have the required role(s)", context.exception.detail)

    def test_do_role_check_with_no_required_roles(self):
        """Test do_role_check when no roles are required."""
        user = {"roles": ["user"]}
        required_roles = []
        try:
            do_role_check(user, required_roles, roles_key='roles')
        except HTTPException as e:
            self.fail(f"do_role_check raised HTTPException unexpectedly: {e}")

    def test_sync_function_call(self):
        """Test calling a synchronous function."""
        result = is_called_from_async_context(sync_function, 5)
        self.assertEqual(result, 10, "The result should be the double of the input for sync function.")

    def test_async_function_call(self):
        """Test calling an asynchronous function."""
        result = asyncio.run(is_called_from_async_context(async_function, 5))
        self.assertEqual(result, 10, "The result should be the double of the input for async function.")

    def test_async_function_with_args(self):
        """Test calling an asynchronous function with multiple arguments."""
        async def async_sum(a, b):
            await asyncio.sleep(0.1)
            return a + b

        result = asyncio.run(is_called_from_async_context(async_sum, 3, 7))
        self.assertEqual(result, 10, "The result should be the sum of the two inputs.")

    def test_sync_function_with_args(self):
        """Test calling a synchronous function with multiple arguments."""
        def sync_sum(a, b):
            return a + b

        result = is_called_from_async_context(sync_sum, 3, 7)
        self.assertEqual(result, 10, "The result should be the sum of the two inputs.")

    def test_do_role_check_with_whitespace_delimited_roles(self):
        """Test do_role_check with a whitespace-delimited roles string."""
        user = {"scp": "admin user editor"}
        required_roles = ["admin", "editor"]
        try:
            do_role_check(user, required_roles, roles_key='scp', value_delimiter=' ')
        except HTTPException as e:
            self.fail(f"do_role_check raised HTTPException unexpectedly: {e}")


if __name__ == "__main__":
    unittest.main()