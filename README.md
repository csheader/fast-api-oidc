# FastAPI Authentication Middleware

## Overview

`fast-api-auth-middleware` is a simple authentication middleware for FastAPI applications. It supports multiple OpenID Connect (OIDC) providers, including custom providers, and allows for role-based access control (RBAC) on routes.

## Features

- **Multiple OIDC Providers**: Supports built-in and custom OIDC providers.
- **Role-Based Access Control**: Secure routes by specifying required roles.
- **Token and JWKS Caching**: Efficient caching mechanisms for tokens and JWKS data.
- **Customizable**: Easily extendable to support additional providers and configurations.

## Installation

To install the package, use pip:

```bash
pip install fast-api-auth-middleware
```

## Usage

### Basic Setup

Here's a basic example of how to use the middleware in a FastAPI application:

For a simple use case it is recommended to use the AuthMiddleware when you only have a single authentication provider type. Here is an example of how to do this with Azure AD B2C with multiple policies:

```python
from fastapi import FastAPI
from fast_api_jwt_middleware.middleware import AuthMiddleware
from fast_api_jwt_middleware.wrapper import secure_route
from fast_api_jwt_middleware.oidc_helper import get_oidc_urls

# Create a FastAPI application
app = FastAPI()

# Azure AD B2C configuration for multiple policies
azure_ad_b2c_configs = [
    {
        "tenant_name": "your-tenant-name",
        "policy_name": "policy1",
        "client_id": "your-client-id"
    },
    {
        "tenant_name": "your-tenant-name",
        "policy_name": "policy2",
        "client_id": "your-client-id"
    }
]

# Use the OIDC helper to get the OIDC URLs for each policy
oidc_urls = get_oidc_urls(
    domains_or_configs=azure_ad_b2c_configs,
    provider_name="AzureAD_B2C"
)

# Add the AuthMiddleware to the FastAPI app for each policy
for oidc_url in oidc_urls:
    app.add_middleware(
        AuthMiddleware,
        oidc_url=oidc_url,
        audience=azure_ad_b2c_configs[0]["client_id"],  # Assuming the same client_id for all policies
        roles_key="roles"  # Adjust this if your roles are stored under a different key
    )

# Define a secure endpoint with role-based access control
@app.get("/secure-endpoint")
@secure_route(required_roles="admin")
async def secure_endpoint():
    return {"message": "You have access to this secure endpoint."}

# Define a public endpoint without authentication
@app.get("/public-endpoint")
async def public_endpoint():
    return {"message": "This is a public endpoint accessible to everyone."}
```

OKTA example:

```python
from fastapi import FastAPI
from fast_api_jwt_middleware.middleware import AuthMiddleware
from fast_api_jwt_middleware.wrapper import secure_route

# Create a FastAPI application
app = FastAPI()

# OKTA configuration
okta_config = {
    "oidc_url": "https://your-okta-domain.com/oauth2/default/.well-known/openid-configuration",
    "audience": "your-audience",
    "roles_key": "roles"  # Adjust this if your roles are stored under a different key
}

# Add the AuthMiddleware to the FastAPI app
app.add_middleware(
    AuthMiddleware,
    oidc_url=okta_config["oidc_url"],
    audience=okta_config["audience"],
    roles_key=okta_config["roles_key"]
)

# Define a secure endpoint with role-based access control
@app.get("/secure-endpoint")
@secure_route(required_roles="admin")
async def secure_endpoint():
    return {"message": "You have access to this secure endpoint."}

# Define a public endpoint without authentication
@app.get("/public-endpoint")
async def public_endpoint():
    return {"message": "This is a public endpoint accessible to everyone."}
```


```python

from fastapi import FastAPI
from fast_api_jwt_middleware.middleware import MultiProviderAuthMiddleware
from fast_api_jwt_middleware.wrapper import secure_route
app = FastAPI()
Example configuration for multiple OIDC providers
providers = [
    {
        "oidc_urls": ["https://example.com/.well-known/openid-configuration"],
        "audiences": ["your-audience"],
        "roles_key": "roles"
    },
    {
        "oidc_urls": ["https://another-example.com/.well-known/openid-configuration"],
        "audiences": ["another-audience"],
        "roles_key": "roles"
    }
]

##Add the MultiProviderAuthMiddleware to the FastAPI app
app.add_middleware(
    MultiProviderAuthMiddleware,
    providers=providers
)
@app.get("/secure-endpoint")
@secure_route(required_roles="admin")
async def secure_endpoint():
    return {"message": "You have access to this secure endpoint."}

```


### Configuration

| Parameter | Description | Default |
| --- | --- | --- |
| oidc_urls | List of well-known OIDC URLs for the identity provider(s). | Required |
| audiences | List of acceptable audiences for the token. | Required |
| token_ttl | Time-to-live for the token cache (in seconds). | 300 |
| jwks_ttl | Time-to-live for the JWKS cache (in seconds). | 3600 |
| oidc_ttl | Time-to-live for the OIDC configuration cache (in seconds). | 3600 |
| token_cache_maxsize | Maximum size of the token cache. | 1000 |
| logger | Custom logger instance for debug and error messages. | None (prints) |
| roles_key | JWT claim key to extract roles (for multi-provider). | roles |

## Error Handling
The middleware returns the following HTTP responses:

`401 Unauthorized`: The token is invalid or missing.

`403 Forbidden`: The user token does not meet the requirements of the security context

`500 Internal Server Error`: Issues occurred when fetching OIDC configurations or JWKS.

## Dependencies

- `fastapi`
- `pyjwt>=2.8.0`
- `cachetools`
- `requests`

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

How to contribute:

1. Fork the repository.

2. Create a new branch for your feature or bug fix.

3. Commit your changes and create a pull request.

## Contact

For questions or support, please contact [csheader](mailto:christopher.sheader@gmail.com).
