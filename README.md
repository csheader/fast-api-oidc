# FastAPI Authentication Middleware

>**NOTE:** This package is under active development.

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

### Exported Classes and Functions

The following classes and functions are available for use in this package:

- **Classes**:
  - `AuthMiddleware`: Middleware for handling authentication with a single OIDC provider.
  - `MultiProviderAuthMiddleware`: Middleware for handling authentication with multiple OIDC providers.
  - `TokenCache`: Handles caching of JWT tokens with a time-to-live (TTL).
  - `TokenCacheSingleton`: A singleton class that provides a global access point to a `TokenCache` instance.
  - `OIDCProvider`: Enum representing various OpenID Connect (OIDC) providers.

### Supported OIDC Providers

The following OIDC providers are currently supported:

| Provider Type         | URL Template                                                                                          | Required Inputs                |
|-----------------------|-------------------------------------------------------------------------------------------------------|--------------------------------|
| **OKTA**              | `https://{domain}/.well-known/openid-configuration`                                                  | `domain`                       |
| **DUO**               | `https://{domain}/oauth/v1/.well-known/openid-configuration`                                        | `domain`                       |
| **ONELOGIN**          | `https://{domain}/oidc/2/.well-known/openid-configuration`                                          | `domain`                       |
| **AZURE AD**          | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`                  | `tenant`                       |
| **AZURE AD B2C**      | `https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration` | `tenant`, `policy`            |
| **GOOGLE**            | `https://accounts.google.com/.well-known/openid-configuration`                                      | None                           |
| **FACEBOOK**          | `https://www.facebook.com/.well-known/openid-configuration`                                         | None                           |
| **GENERIC**           | `{base_url}/.well-known/openid-configuration`                                                       | `base_url`                    |
| **AMAZON COGNITO**    | `https://{user_pool_id}.auth.{region}.amazoncognito.com/.well-known/openid-configuration`          | `user_pool_id`, `region`      |
| **AUTH0**             | `https://{domain}/.well-known/openid-configuration`                                                  | `domain`                       |
| **PING IDENTITY**     | `https://{domain}/.well-known/openid-configuration`                                                  | `domain`                       |
| **IBM SECURITY VERIFY**| `https://{tenant}.verify.ibm.com/v2.0/.well-known/openid-configuration`                             | `tenant`                       |
| **SALESFORCE**        | `https://{instance}.my.salesforce.com/.well-known/openid-configuration`                             | `instance`                     |
| **KEYCLOAK**          | `https://{domain}/auth/realms/{realm}/.well-known/openid-configuration`                             | `domain`, `realm`             |
| **GITHUB**            | `https://token.actions.githubusercontent.com/.well-known/openid-configuration`                       | None                           |

### Functions

- `get_oidc_urls(domains_or_configs: List[dict] | dict, provider_name: str)`: Constructs OIDC discovery URLs for both built-in and custom providers.
- `register_custom_provider(name: str, url_template: str, required_fields: List[str])`: Registers a custom OIDC provider.

### Using `get_oidc_urls`

The `get_oidc_urls` function constructs OIDC discovery URLs based on the provided configuration and provider name. Here’s how to use it:

```python
from fast_api_jwt_middleware.oidc_helper import get_oidc_urls

# Example configuration for Azure AD B2C
azure_ad_b2c_configs = [
    {
        "tenant": "your-tenant-name",
        "policy": "policy1"
    },
    {
        "tenant": "your-tenant-name",
        "policy": "policy2"
    }
]

# Get OIDC URLs for Azure AD B2C
oidc_urls = get_oidc_urls(domains_or_configs=azure_ad_b2c_configs, provider_name="AZURE_AD_B2C")

print(oidc_urls)
```

### Registering Custom OIDC Providers

You can register custom OIDC providers using the `register_custom_provider` function. Here’s an example:

```python
from fast_api_jwt_middleware.oidc_providers import register_custom_provider

# Register a custom OIDC provider
register_custom_provider(
    name="CustomProvider",
    url_template="https://{custom_domain}/.well-known/openid-configuration",
    required_fields=["custom_domain"]
)

# Example usage of the custom provider
custom_config = {
    "custom_domain": "example.com"
}

# Get OIDC URLs for the custom provider
oidc_urls = get_oidc_urls(domains_or_configs=custom_config, provider_name="CustomProvider")

print(oidc_urls)
```

### Basic Setup with `AuthMiddleware`

Here's a basic example of how to use the `AuthMiddleware` in a FastAPI application for a simple use case:

```python
from fastapi import FastAPI
from fast_api_jwt_middleware import AuthMiddleware, secure_route
from fast_api_jwt_middleware.oidc_helper import get_oidc_urls

# Create a FastAPI application
app = FastAPI()

# Azure AD B2C configuration for a single policy
azure_ad_b2c_config = {
    "tenant": "your-tenant-name",
    "policy": "policy1"
}

# Get OIDC URL for Azure AD B2C
oidc_url = get_oidc_urls(domains_or_configs=azure_ad_b2c_config, provider_name="AZURE_AD_B2C")

# Add the AuthMiddleware to the FastAPI app
app.add_middleware(
    AuthMiddleware,
    oidc_urls=[oidc_url],
    audiences=["your-client-id"],  # Replace with your actual client ID
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

### Complex Setup with `MultiProviderAuthMiddleware`

For a more complex use case with multiple OIDC providers, you can use the `MultiProviderAuthMiddleware`. Here’s how to set it up:

```python
from fastapi import FastAPI
from fast_api_jwt_middleware import MultiProviderAuthMiddleware, secure_route
from fast_api_jwt_middleware.oidc_helper import get_oidc_urls

# Create a FastAPI application
app = FastAPI()

# Azure AD B2C configuration for multiple policies
azure_ad_b2c_configs = [
    {
        "tenant": "your-tenant-name",
        "policy": "policy1"
    },
    {
        "tenant": "your-tenant-name",
        "policy": "policy2"
    }
]

# Use the OIDC helper to get the OIDC URLs for each policy
oidc_urls = get_oidc_urls(domains_or_configs=azure_ad_b2c_configs, provider_name="AZURE_AD_B2C")

# Add the MultiProviderAuthMiddleware to the FastAPI app for each policy
app.add_middleware(
    MultiProviderAuthMiddleware,
    providers=[{"oidc_urls": oidc_urls, "audiences": ["your-client-id","your-other-client-id"]}],  # Replace with your actual client ID(s)
    roles_key="roles",  # Adjust this if your roles are stored under a different claim
    excluded_paths=['/public-endpoint'] #Paths which you would not like to perform any auth checks
)



# Define a secure endpoint with role-based access control
@app.get("/secure-endpoint")
@secure_route(required_roles="admin")
async def secure_endpoint():
    return {"message": "You have access to this secure endpoint."}

# Define another secure endpoint with different role requirements
@app.get("/another-secure-endpoint")
@secure_route(required_roles=["admin", "editor"])
async def another_secure_endpoint():
    return {"message": "You have access to this secure endpoint as an admin or editor."}

# Define another secure endpoint with different role requirements and claim keys
@app.get("/yet-another-secure-endpoint")
@secure_route(required_roles=["superadmin"], role_key='permissions')
async def another_secure_endpoint():
    return {"message": "You have access to this secure endpoint as an admin or editor."}

# Define another endpoint that only validates the
# JWT and does not have any role requirements
@app.get("/yet-another-secure-endpoint")
@secure_route()
async def another_secure_endpoint():
    return {"message": "You have access to this secure endpoint as an admin or editor."}

# Define a public endpoint without authentication
# to avoid jwt auth, the path must be defined in the
# excluded_paths for the middleware
@app.get("/public-endpoint")
async def public_endpoint():
    return {"message": "This is a public endpoint accessible to everyone."}
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
| logger | Logger for debug information during the authentication lifecycle. | logging.Logger |

### Securing routes with `secure_route`

When you have specific routes that need to be secured for different methods of authentication or based on specific roles within your JWT, you can use the `secure_route` from this library. 

Example:

```python
from fast_api_jwt_middleware.wrapper import secure_route

# secured endpoint, uses the default roles_key in the
# middleware or the "roles" claim on the token
@app.get("/secure-endpoint")
@secure_route(required_roles="admin")
async def secure_endpoint():
    return {"message": "You have access to this secure endpoint."}

# secured endpoint, uses the roles_key from the route
# in place of the default roles key from the middleware
@app.get("/secure-endpoint")
@secure_route(required_roles="admin", roles_key='permissions')
async def secure_endpoint():
    return {"message": "You have access to this secure endpoint."}

#unsecured endpoint, if a token is passed it will still be cached
@app.get("/secure-endpoint")
async def secure_endpoint():
    return {"message": "You have access to this secure endpoint."}


```

## Error Handling
The middleware returns the following HTTP responses:

- `401 Unauthorized`: The token is invalid or missing.
- `403 Forbidden`: The user token does not meet the requirements of the security context.
- `500 Internal Server Error`: Issues occurred when fetching OIDC configurations or JWKS.

## Dependencies

- `fastapi`
- `pyjwt>=2.8.0`
- `cachetools`
- `requests`
- `cryptography`

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
