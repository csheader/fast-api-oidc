import inspect
from fastapi import HTTPException, status
from functools import wraps
from typing import Callable, List, Union
from fast_api_jwt_middleware.context_holder import request_context

def is_called_from_async_context(func: Callable, *args, **kwargs):
    '''
    Calls a function that can be either synchronous or asynchronous.

    :param func: The function to call (can be sync or async).
    :param args: Positional arguments to pass to the function.
    :param kwargs: Keyword arguments to pass to the function.
    :return: The result of the function call.
    '''
    if inspect.iscoroutinefunction(func):
        # If it's async, await it directly
        return func(*args, **kwargs)  # Do not use asyncio.run(), the world blows up.
    else:
        # If it's sync, just call it directly
        return func(*args, **kwargs)

def do_role_check(user, required_roles: str | List[str], roles_key: str, value_delimiter: str= None):
    '''
    Checks if the user has the required roles to access a resource.

    :param user: The user object containing role information.
    :param required_roles: The roles required to access the resource.
    :param roles_key: The key in the token where roles are stored.
    :param value_delimiter: The delimiter used to separate roles in the user_roles string (default: None).
    :raises HTTPException: If the user does not have the required role(s), a 403 Forbidden error is raised.
    
    This function retrieves the roles associated with the user and checks them against the 
    required roles. If the user's roles do not include any of the required roles, an 
    HTTPException is raised indicating that access is forbidden.

    The `roles_key` variable should be defined in the scope where this function is called, 
    indicating where to find the user's roles in the user object.

    The `required_roles` variable should also be defined in the scope where this function is 
    called, indicating the roles that are necessary for access.
    '''
    user_roles = user.get(roles_key, [])
    if isinstance(user_roles, str):
        if value_delimiter:
            user_roles = user_roles.split(value_delimiter)
        else:
            user_roles = [user_roles]
    elif isinstance(user_roles, list):
        user_roles = user_roles
    else:
        user_roles = []

    if isinstance(required_roles, str):
        allowed_roles = [required_roles]
    elif isinstance(required_roles, list):
        allowed_roles = required_roles
    else:
        allowed_roles = []

    if allowed_roles and not any(role in user_roles for role in allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You do not have the required role(s) to access this resource. Required role(s): {', '.join(allowed_roles)}."
        )

def secure_route(
    required_roles: Union[str, List[str]] = None,
    roles_key: str = 'roles',
    value_delimiter: str = None
) -> Callable:
    '''
    A decorator to secure routes by checking the user's roles.

    :param required_roles: A single role or a list of roles required for accessing the route.
    :param roles_key: The key in the token where roles are stored (default: 'roles').
    :param value_delimiter: The delimiter used to separate roles in the user_roles string (default: None).
    '''
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get('request')
            if not request:
                # If not found, try to get it from the context variable
                request = request_context.get(None)
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found. Please evaluate your code to validate that a request context is available."
                )
            user = getattr(request.state, 'user', None)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='User information not received in the request.'
                )
            # Use the roles_key from the wrapper if provided, otherwise use the default
            effective_roles_key = kwargs.get('roles_key', roles_key)
            do_role_check(user, required_roles, effective_roles_key, value_delimiter)
            maybe_async = is_called_from_async_context(func, *args, **kwargs)
            if inspect.iscoroutine(maybe_async):
                return await maybe_async
            return maybe_async

        return wrapper

    return decorator
