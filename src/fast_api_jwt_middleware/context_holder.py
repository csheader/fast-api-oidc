from contextvars import ContextVar

request_context = ContextVar('request_context')

"""
The request_context variable is a ContextVar that holds the context of the current request.
It allows for storing and retrieving request-specific data in an asynchronous environment.

This is used in the auth_middleware and wrapper modules. This context is used to add
the request if one is not provided in the method constructor for the route implementation
in the controller method for FastAPI. 

This provides support for both of these cases:

@app.get('/api/some-route')
async def some_controller_method(request: Request)
    ...


@app.get('/api/some-other-route')
async def some_controller_method():
    ... 
"""