class NtlmCredentials:
    """
    The Credentials object represents the necessary credentials
    for authenticating with NTLM.
    """

    def __init__(self, username, domain, password):
        self.username = username
        self.password = password
        self.domain = domain

    def is_valid(self):
        """
        Check to see if these credentials are valid.
        :return: **True** if the credentials are valid.
        """
        return self.username and self.password and self.domain
