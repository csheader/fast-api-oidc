from fastapi import Request, HTTPException, status
from functools import wraps
from typing import Callable, List, Union


def secure_route(
    required_roles: Union[str, List[str]] = None,
    roles_key: str = "roles"
) -> Callable:
    """
    A decorator to secure routes by checking the user's roles.

    :param required_roles: A single role or a list of roles required for accessing the route.
    :param roles_key: The key in the token where roles are stored (default: "roles").
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found. Ensure 'request' is passed to your route."
                )
            user = getattr(request.state, "user", None)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User information not received in the request."
                )
            
            # get the roles from the provided key (if different from default of roles)
            user_roles = user.get(roles_key, [])
            if isinstance(user_roles, str):
                user_roles = [user_roles]

            if isinstance(required_roles, str):
                allowed_roles = [required_roles]
            elif isinstance(required_roles, list):
                allowed_roles = required_roles
            else:
                allowed_roles = []

            # Check if the user's roles include any of the required roles
            if allowed_roles and not any(role in user_roles for role in allowed_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"You do not have the required role(s) to access this resource. Required role(s): {', '.join(allowed_roles)}."
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
