class HTTPException(Exception):
    """
    Wrapper class for HTTP exceptions
    """
    def __init__(self, code, message=""):
        super().__init__(message)
        self.code = code

class AniMalUserNotFoundException(Exception):
    """
    Raised when an AniMalUser is not found in the database.
    """
    def __init__(self, user_id):
        """
        Args:
            user_id (int): User ID that was failed to be found.
        """
        message = f"Failed to find user with id {user_id}"
        super().__init__(message)

class MalUnauthorizedException(Exception):
    """
    Raised when an AniMalUser has not authorized AniMalSync for MAL.
    """
    def __init__(self, user_id):
        """
        Args:
            user_id (int): User ID of user
        """
        message = f"User {user_id} has not authorized AniMalSync for MAL."
        super().__init__(message)

class EmailNotVerifiedException(Exception):
    """
    Raised when an AniMalUser has not verified their email.
    """
    def __init__(self, user_id):
        """
        Args:
            user_id (int): User ID of user
        """
        message = f"User {user_id} has not verified their email."
        super().__init__(message)