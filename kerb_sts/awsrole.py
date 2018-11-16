# Copyright 2016 Commerce Technologies, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class AWSRole:
    """
    The AWSRole is parsed from the Active Directory login page. It contains
    the ARN of the IAM Role and the name of the SAML Provider. This class allows
    the code to manage that parsing and access.
    """

    ARN_PART_INDEX = 0
    PROVIDER_PART_INDEX = 1
    ACCOUNT_PART_INDEX = 4
    ROLE_PART_INDEX = 5
    ROLE_NAME_PART_INDEX = -1

    def __init__(self, aws_role):
        """
        Create a new Role object and parse the specified role into is parts.
        :param aws_role: the text from the IdP login page
        """
        if not self._parse(aws_role):
            msg = "The 'aws_role' is not valid: {0}".format(aws_role)
            raise ValueError(msg)

    def _parse(self, aws_role):
        """
        Parse the role string and return True if parsing succeeded.
        :param aws_role: the Role ARN from AWS
        :return: **True** if the role string can be parsed, otherwise **False**
        """
        if not aws_role:
            return False

        parts = aws_role.split(',')

        if len(parts) != 2:
            return False

        arn = parts[AWSRole.ARN_PART_INDEX]
        provider = parts[AWSRole.PROVIDER_PART_INDEX]

        if len(arn) <= 0:
            return False

        if len(provider) <= 0:
            return False

        # ARNs are of the form 'arn:aws:iam::account-id:role/path/role-name'
        # if path == '/' then a single slash ('/') appears between the "role"
        # keyword and the name of the role

        arn_parts = arn.split(':')

        if len(arn_parts) != 6:
            return False

        account = arn_parts[AWSRole.ACCOUNT_PART_INDEX]
        role_parts = arn_parts[AWSRole.ROLE_PART_INDEX].split('/')

        if len(role_parts) < 2:
            return False

        name = role_parts[AWSRole.ROLE_NAME_PART_INDEX]

        self.arn = arn
        self.provider = provider
        self.account = account
        self.name = name
        self.profile = "{}.{}".format(account, name)

        return True
