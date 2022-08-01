class Auth0ConnectionError(Exception):
    """
    An error when attempting to connect to Auth0.
    """

    pass


class Auth0OperationError(Exception):
    """
    A problem when attempting to perform an operation in Auth0.
    """

    pass
