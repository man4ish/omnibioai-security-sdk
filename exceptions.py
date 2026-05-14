class SecurityException(Exception):
    pass


class Unauthorized(SecurityException):
    pass


class Forbidden(SecurityException):
    pass