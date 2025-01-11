# FastAPI JWT Middleware

>**NOTE:** This package is under active development.

## Overview

`fast-api-jwt-middleware` is a simple authentication middleware for FastAPI applications. It supports multiple OpenID Connect (OIDC) providers, including custom providers, and allows for role-based access control (RBAC) on routes.

This library provides a fully featured RBAC set of controls for OIDC Identity Providers within the FastAPI ecosystem.

## Features

- **Multiple OIDC Providers**: Supports built-in and custom OIDC providers.
- **Role-Based Access Control**: Secure routes by specifying required roles.
- **Token and JWKS Caching**: Efficient caching mechanisms for tokens and JWKS data.
- **Customizable**: Easily extendable to support additional providers and configurations.

## Installation

To install the package, use pip:

```bash
pip install fast-api-jwt-middleware
```

## Usage

### Exported Classes and Functions

The following classes and functions are available for use in this package:

- **Classes**:
  - `AuthMiddleware`: Middleware for handling authentication with a single OIDC provider.
  - `MultiProviderAuthMiddleware`: Middleware for handling authentication with multiple OIDC providers.
  - `TokenCache`: Handles caching of JWT tokens with a time-to-live (TTL). Internal implementation but exposed for reuse if a user would like to reuse the implementation.
  - `TokenCacheSingleton`: A singleton class that provides a global access point to a `TokenCache` instance.
  - `OIDCProvider`: Enum representing various OpenID Connect (OIDC) providers.

### Functions

- `get_oidc_urls(domains_or_configs: List[dict] | dict, provider_name: str)`: Constructs OIDC discovery URLs for both built-in and custom providers.
- `register_custom_provider(name: str, url_template: str, required_fields: List[str])`: Registers a custom OIDC provider.

### Interfaces / Protocols

Given that we, as software engineers, need flexibility we provide a way to provide your own logger and caching mechanism. These act like interfaces in other code, but we use them for DuckTyping in Python. These types define the contract that we expect for the logger and the token cache. 

- `LoggerProtocol`: Provides the contract for the required methods on a Logger that is passed to the middleware. By default all messages are written to the debug level so your log_level will need to be set to "DEBUG" to see them for your provided logger type.
- `CacheProtocol`: Provides the contract for the required methods on a TokenCache object that is passed to the middleware. By default a cachetools TTLCache is used for caching tokens for this package.

### Supported OIDC Providers

The following OIDC providers are currently supported by default by this library, if it is not listed below please open an issue or create a PR to add it. If the provider is widely used then we will add it to the default list. You can always use the Generic provider or create your own [CUSTOMPROVIDER](#registering-custom-oidc-providers) in the interim if the provider does not currently exist within the supported OIDC provider list.

Note that only OIDC providers will be supported by this library:

| Provider Type         | ENUM Value | URL Template                                                                                          | Required Inputs                |
| --------------------- | ----- |----------------------------------------------------------------------------------------------------- | ------------------------------ |
| **OKTA**              | OKTA | `https://{domain}/.well-known/openid-configuration`                                                  | `domain`                       |
| **DUO**               | DUO | `https://{domain}/oauth/v1/.well-known/openid-configuration`                                        | `domain`                       |
| **ONELOGIN**          | ONELOGIN | `https://{domain}/oidc/2/.well-known/openid-configuration`                                          | `domain`                       |
| **AZURE AD**          | AZURE_AD | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`                  | `tenant`                       |
| **AZURE AD B2C**      | AZURE_AD_B2C |`https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration` | `tenant`, `policy`            |
| **GOOGLE**            | GOOGLE | `https://accounts.google.com/.well-known/openid-configuration`                                      | None                           |
| **FACEBOOK**          | FACEBOOK | `https://www.facebook.com/.well-known/openid-configuration`                                         | None                           |
| **GENERIC**           | GENERIC | `{base_url}/.well-known/openid-configuration`                                                       | `base_url`                    |
| **AMAZON COGNITO**    | AMAZON_COGNITO | `https://{user_pool_id}.auth.{region}.amazoncognito.com/.well-known/openid-configuration`          | `user_pool_id`, `region`      |
| **AUTH0**             | AUTH0 | `https://{domain}/.well-known/openid-configuration`                                                  | `domain`                       |
| **PING IDENTITY**     | PING_IDENTITY | `https://{domain}/.well-known/openid-configuration`                                                  | `domain`                       |
| **IBM SECURITY VERIFY**| IBM_SECURITY_VERIFY | `https://{tenant}.verify.ibm.com/v2.0/.well-known/openid-configuration`                             | `tenant`                       |
| **SALESFORCE**        | SALESFORCE | `https://{instance}.my.salesforce.com/.well-known/openid-configuration`                             | `instance`                     |
| **KEYCLOAK**          | KEYCLOAK | `https://{domain}/auth/realms/{realm}/.well-known/openid-configuration`                             | `domain`, `realm`             |
| **GITHUB**            | GITHUB | `https://token.actions.githubusercontent.com/.well-known/openid-configuration`                       | None                           |

>This list is limited, but you can use the GENERIC provider in a lot of contexts or create your own CUSTOMPROVIDER to handle your specific situation.


### Using `get_oidc_urls`

Fundamentally, authentication can be fairly complex. To provide a little bit of usability to this library we have provided a function to construct the oidc urls for you. 

This function will return the formatted .wellknown endpoint for supported providers. Additionally, if you register a custom provider this function will continue to function as expected.

The `get_oidc_urls` function is a convenience method for users who do not know how to format their .wellknown url for their provider. These url's are consistent depending on your IdP and can be configured appropriately. Given the number of potential combinations and providers it is likely that yours may not exist in this list. If this is the case, you will want to use a GENERIC provider, or a [CUSTOMPROVIDER](#registering-custom-oidc-providers). As always, if you feel that the provider should be added to the default list please open an issue to have it added to the default list.

The `get_oidc_urls` function constructs OIDC discovery URLs based on the provided configuration and provider name. Here’s how to use it:

```python
from fast_api_jwt_middleware import get_oidc_urls

# Example configuration for Azure AD B2C
azure_ad_b2c_configs = [
    {
        "tenant": "your-tenant-name",
        "policy": "B2C_1A_policy1"
    },
    {
        "tenant": "your-tenant-name",
        "policy": "B2C_1A_policy2"
    }
]

# Get OIDC URLs for Azure AD B2C
oidc_urls = get_oidc_urls(domains_or_configs=azure_ad_b2c_configs, provider_name="AZURE_AD_B2C")

print(oidc_urls)
```

### Registering Custom OIDC Providers

You can register custom OIDC providers using the `register_custom_provider` function. Here’s an example:

```python
from fast_api_jwt_middleware import register_custom_provider

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
# [https://CustomProvider/.well-known/openid-configuration/]
```

### Basic Setup with `AuthMiddleware`

Here's a basic example of how to use the `AuthMiddleware` in a FastAPI application for a simple use case:

```python
from fastapi import FastAPI
from fast_api_jwt_middleware import AuthMiddleware, secure_route, get_oidc_urls

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
    roles_key="roles",  # Adjust this if your roles are stored under a different key
    excluded_paths=["/public-endpoint"]
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
async def yet_another_secure_endpoint():
    return {"message": "You have access to this secure endpoint as an admin or editor."}

# Define another endpoint that only validates the
# JWT and does not have any role requirements
@app.get("/yet-even-another-secure-endpoint")
@secure_route()
async def yet_even_another_secure_endpoint():
    return {"message": "You have access to this secure endpoint as an admin or editor."}

# Define a public endpoint without authentication
# to avoid jwt auth, the path must be defined in the
# excluded_paths for the middleware
@app.get("/public-endpoint")
async def public_endpoint():
    return {"message": "This is a public endpoint accessible to everyone."}
```

#### Single Auth Provider with Multiple Audiences

The most common scenario that a developer will run into is one in which a single IdP is used for their applications but multiple audiences (applications) are able to access the endpoint. 

In this case, you can still use the `AuthMiddleware`:

```python
from fastapi import FastAPI
from fast_api_jwt_middleware import AuthMiddleware, secure_route, get_oidc_urls

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
    audiences=["client-id-2", "client-id-2", "client-id-n"],  # Replace with your actual client IDs, up to N clients
    roles_key="roles",  # Adjust this if your roles are stored under a different key
    excluded_paths=["/public-endpoint"]
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
async def yet_another_secure_endpoint():
    return {"message": "You have access to this secure endpoint as an admin or editor."}

# Define another endpoint that only validates the
# JWT and does not have any role requirements
@app.get("/yet-even-another-secure-endpoint")
@secure_route()
async def yet_even_another_secure_endpoint():
    return {"message": "You have access to this secure endpoint as an admin or editor."}

# Define a public endpoint without authentication
# to avoid jwt auth, the path must be defined in the
# excluded_paths for the middleware
@app.get("/public-endpoint")
async def public_endpoint():
    return {"message": "This is a public endpoint accessible to everyone."}
```

### Complex Setup with `MultiProviderAuthMiddleware`

For a more complex use case with multiple OIDC providers, you can use the `MultiProviderAuthMiddleware`. Here’s how to set it up:

```python
from fastapi import FastAPI
from fast_api_jwt_middleware import MultiProviderAuthMiddleware, secure_route, get_oidc_urls

# Create a FastAPI application
app = FastAPI()

# Setup Azure AD / Entra ID as the services audience
azure_ad_config = {
    "tenant": "your-tenant-name"  # Replace with your Azure AD tenant name
}

# Azure AD B2C configuration for multiple policies
azure_ad_b2c_configs = [
    {
        "tenant": "your-tenant-name",  # Replace with your Azure AD B2C tenant name
        "policy": "B2C_1A_policy1"      # Replace with your Azure AD B2C policy
    },
    {
        "tenant": "your-tenant-name",  # Replace with your Azure AD B2C tenant name
        "policy": "B2C_1A_policy2"      # Replace with your Azure AD B2C policy
    }
]

# Get OIDC URL for Azure AD
oidc_url_azure_ad = get_oidc_urls(domains_or_configs=azure_ad_config, provider_name="AZURE_AD")

# Get OIDC URLs for Azure AD B2C
oidc_urls_azure_ad_b2c = get_oidc_urls(domains_or_configs=azure_ad_b2c_configs, provider_name="AZURE_AD_B2C")

# Add the MultiProviderAuthMiddleware to the FastAPI app for both providers
app.add_middleware(
    MultiProviderAuthMiddleware,
    providers=[
        {"oidc_urls": [oidc_url_azure_ad], "audiences": ["your-client-id", "your-client-id-2"]},  # Replace with your actual Azure AD client ID
        {"oidc_urls": oidc_urls_azure_ad_b2c, "audiences": ["your-client-id-b2c","another-client-id"]}  # Replace with your actual Azure AD B2C client ID
    ],
    roles_key="roles",  # Adjust this if your roles are stored under a different claim
    excluded_paths=["/public-endpoint"]  # Paths which you would not like to perform any auth checks
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

# Define a public endpoint without authentication
@app.get("/public-endpoint")
async def public_endpoint():
    return {"message": "This is a public endpoint accessible to everyone."}
```

The above example uses Azure AD B2C and Azure AD, but this is interchangeable with any provider. The important part is that you setup your providers appropriately and with the correct audiences. The token construction is also important so bear in mind that you may need to override specific methods with differing RBAC considerations.


### AuthMiddleware and MultiProviderAuthMiddleware Configuration

| Parameter | Description | Default |
| --- | --- | --- |
| oidc_urls | List of well-known OIDC URLs for the identity provider(s). | Required |
| audiences | List of acceptable audiences for the token. | Required |
| token_ttl | Time-to-live for the token cache (in seconds). | 300 |
| jwks_ttl | Time-to-live for the JWKS cache (in seconds). | 3600 |
| oidc_ttl | Time-to-live for the OIDC configuration cache (in seconds). | 3600 |
| token_cache_maxsize | Maximum size of the token cache. | 1000 |
| custom_token_cache | Your own implementation of the `CacheProtocol` for handling and caching tokens. | None |
| logger | Logger for debug information during the authentication lifecycle. This logger must implement the `LoggerProtocol` contract exported from this project to be used. Only debug messages are propagated from this library if the logger's debug flag is enabled. | logging.Logger |
| excluded_paths | Paths which should remain public for your application and do not require authentication. | [] |
| roles_key | Default roles key for your `@secure_route` routes within your application. If the route is not in the excluded paths it will still execute jwt auth and require a valid token. | "roles" | 

### Securing routes with `secure_route`

When you have specific routes that need to be secured for different methods of authentication or based on specific roles within your JWT, you can use the `secure_route` from this library. 

Example:

```python
from fast_api_jwt_middleware import secure_route

# secured endpoint, uses the default roles_key in the
# middleware or the "roles" claim on the token
@app.get("/api/secured-endpoint-roles-check")
@secure_route(required_roles="admin")
async def secure_endpoint_roles_check():
    return {"message": "You have access to this secure endpoint."}

# secured endpoint, uses the roles_key from the route
# in place of the default roles key from the middleware
@app.get("/secure-endpoint-different-roles-key")
@secure_route(required_roles="admin", roles_key='permissions')
async def secure_endpoint_different_roles_key():
    return {"message": "You have access to this secure endpoint."}

# This endpoint is still secured, if a token is passed it will
# still be cached and validated.
# The only way to avoid authentication on an endpoint is to
# put it in the middleware's `excluded_paths` option
@app.get("/secure-endpoint-no-options")
async def secure_endpoint_no_options():
    return {"message": "You have access to this secure endpoint."}


```

### Using `value_delimiter` in `secure_route`

The `secure_route` decorator also supports a `value_delimiter` option, which allows you to specify a delimiter used to separate roles in the user roles string. This is useful when roles are stored as a single string with a specific delimiter.

Example:

from fast_api_jwt_middleware import secure_route

```python
# secured endpoint, uses a whitespace delimiter for roles
@app.get("/secure-endpoint-whitespace-delimiter")
@secure_route(required_roles="admin", roles_key='scp', value_delimiter=' ')
async def secure_endpoint_whitespace_delimiter():
    return {"message": "You have access to this secure endpoint."}

# secured endpoint, uses a comma delimiter for roles
@app.get("/secure-endpoint-comma-delimiter")
@secure_route(required_roles="admin", roles_key='scp', value_delimiter=',')
async def secure_endpoint_comma_delimiter():
    return {"message": "You have access to this secure endpoint."}
```

In the above examples, the `value_delimiter` parameter is used to split the roles string into a list of roles. This allows the `secure_route` decorator to correctly check if the user has the required roles to access the endpoint.

### Accessing Token Properties

This library also will add the token properties to the request.state in fast api as a part of the authentication process. If you need to access specific information off of your token you will need to understand your token's structure. By defauls all claims from the token are added as properties to the user object on the state property. 

This library uses pyjwt for decoding and authentication of tokens. With that being said the token properties that exist on the request.state.user are a direct copy of the output of the jwt.decode method.

An example of how to access token properties:

```python

# Token claims can be accessed on any endpoint
# when the middleware is in use and the path is
# not in the `excluded_paths` option in the middleware
# setup.
# This is the object that is returned from the
# pyjwt decode operation. 
# All claims from your token exist on the Request
# state in FastAPI.
# 
# You must have a request parameter for your
# implementation to access the request.state   
@app.get("/secure-endpoint-no-options")
async def secure_endpoint_no_options(request: Request):
    # grab the user from state
    user_token_object = request.state.user

    # access properties
    email = user_token_object['email']
    sub = user_token_object['sub']
    issuer = user_token_object['iss']
    audience = user_token_object['aud']
    expiration = user_token_object['exp']

    # assuming you have roles on your token
    roles = user_token_object['roles']

    # if you have specific roles on the object, or other properties
    # you can access them from the state object
    some_custom_property = user_token_object['your-claim-property-name']
    return {"message": f"You have access to this endpoint, your email is {email}, token expires at {expiration}"}

```

### Cache operations

This library uses a singleton to manage an in memory cache for the tokens. These tokens are cached for the token_ttl that is provided to the middleware when you add it to your FastAPI application. Both maxsize and the time to live (TTL) are exposed for your use.

The cache is exposed to allow for debugging and cache operations for the users of this library. Specific scenarios where this is useful outside of debugging is to remove a token from the cache during logout, cycling tokens out of the cache out of band when risky behavior is detected or under specific business requirements. Another common scenario is when your provider does not invalidate access tokens even after a refresh token has been invalidate. In this case, it is the developer's responsibility to remove the token from the cache before the TTL expires.

#### Cache operation examples:

```python
from fast_api_jwt_middleware import TokenCacheSingleton

# The cache is instantiated by the library by default.
# You do not need to instantiate the cache to perform
# operations.
token_object = {'token':'your_token', 'decoded_token': { ...your decoded token properties ... } }

# token added to the cache
TokenCacheSingleton.add_token(token_object['token'], token_object['decoded_token'])
# token retrieved from the cache
decoded_token = TokenCacheSingleton.get_token(token_object['token'])
# remove token
TokenCacheSingleton.remove_token(token_object['token'])

# returns None for the token if it has been removed
token_does_not_exist = TokenCacheSingleton.get_token(token_object['token'])

# get the first 100 entries from the token cache
token_list = TokenCacheSingleton.list_tokens(page=1, page_size=100)

# The response of this function is an object with the following shape:
# {
#     "total_tokens": int,
#     "total_pages": int,
#     "current_page": int,
#     "tokens": {
#         token: {
#             "value": object (decoded token),
#             "expiration": int (TTL)
#         }
#     }
# }

# clear all cache
TokenCacheSingleton.clear()

```

### BYOC (Bring Your Own Cache)

This library supports injecting your own cache provider into the AuthMiddleware. To inject your own cache implementation into the middleware you must use the `custom_token_cache` property when setting up the middleware. Any custom_token_cache **must** implement the CacheProtocol contract. 

The CacheProtocol contract defines the properties which are required for the TokenCacheSingleton to manage the cache. 

An example of this implementation is below:

`memory_cache.py`

```python

# In Memory Token Cache implementation for providing your own cache
# For this example this file will be in a file named memory_cache.py
from typing import Any, Optional, Dict
from fast_api_jwt_middleware import CacheProtocol

class InMemoryTokenCache(CacheProtocol):
    def __init__(self) -> None:
        self._cache: Dict[str, Any] = {}

    def add_token(self, token: str, value: Any) -> None:
        self._cache[token] = value

    def get_token(self, token: str) -> Optional[Any]:
        return self._cache.get(token)

    def remove_token(self, token: str) -> bool:
        if token in self._cache:
            del self._cache[token]
            return True
        return False

    def clear(self) -> None:
        self._cache.clear()

    def list_tokens(self, page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        start = (page - 1) * page_size
        end = start + page_size
        return dict(list(self._cache.items())[start:end])
```

`app.py`

```python
from fastapi import FastAPI
from fast_api_jwt_middleware import AuthMiddleware, get_oidc_urls
from .memory_cache import InMemoryTokenCache

app = FastAPI()

# Create an instance of your custom cache
custom_cache = InMemoryTokenCache()

# Example OIDC configuration
oidc_config = {
    "tenant": "your-tenant-name",
    "policy": "policy1"
}

# Get OIDC URL for Azure AD B2C
oidc_url = get_oidc_urls(domains_or_configs=oidc_config, provider_name="AZURE_AD_B2C")

# Add the AuthMiddleware to the FastAPI app with the custom cache
app.add_middleware(
    AuthMiddleware,
    oidc_urls=[oidc_url],
    audiences=["your-client-id"],  # Replace with your actual client ID
    roles_key="roles",
    excluded_paths=["/public-endpoint"],
    token_cache=custom_cache  # Injecting the custom cache
)
```

This is just an example of how to use the cache protocol. It is more likely that you would like to inject a centralized cache of some sort using redis or memcached for your caching layer. However, the steps remain the same for injecting this type of cache.


## Error Handling
The middleware returns the following HTTP responses:

- `401 Unauthorized`: The token is invalid or missing.
- `403 Forbidden`: The user token does not meet the requirements of the security context.
- `500 Internal Server Error`: Issues occurred when fetching OIDC configurations or JWKS.

### Expected Exceptions

| Exception Type | Meaning | Resolution / Root Cause | Source File | Process | Expected Messages |
|----------------|---------|-------------------------|--------------|---------|-------------------|
| `ValueError`   | Raised when an invalid value is provided, such as an unknown provider name or missing required fields. | Check the input values for correctness and ensure all required fields are provided. | `OIDCHelper` | `get_oidc_urls` | "Unknown provider '{provider_name}'." <br> "Missing required fields {missing_fields} for {provider_name}." <br> "Parameter 'oidc_urls' must be a non-empty list of OIDC URLs." <br> "Parameter 'audiences' must be a non-empty list of audience strings."|
| `TypeError`    | Raised when an argument of an inappropriate type is passed, such as a logger that does not implement the required protocol. | Ensure that the correct types are used for all parameters, especially for custom loggers. | `AuthMiddleware` | `__init__` | "Logger must implement the logging protocol." |
| `InvalidTokenError` | Raised when the provided JWT token is invalid or cannot be decoded. | Verify that the token is correctly formatted and valid. | `AuthMiddleware` | `decode_token` | "No token provided." <br> "Token is invalid." <br> "Invalid token: Key not found." |
| `ExpiredSignatureError` | Raised when the JWT token has expired. | Ensure that the token is refreshed or reissued before it expires. | `AuthMiddleware` | `decode_token` | "Token has expired." |
| `HTTPException` | Raised when access is denied due to insufficient roles or other authorization issues. | Check the user's roles against the required roles for the endpoint. | `fast_api_jwt_middleware/wrapper.py` | `@secure_route` or `do_role_check` | "You do not have the required role(s) to access this resource." <br> "User information not received in the request." |


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
