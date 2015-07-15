class CannotHandleAssertion(Exception):
    """
    This processor does not handle this assertion.
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)

class UserNotAuthorized(Exception):
    """
    User not authorized for SAML 2.0 authentication.
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)
