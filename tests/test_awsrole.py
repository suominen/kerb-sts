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

import unittest
from kerb_sts.awsrole import AWSRole


class TestAWSRoleCreation(unittest.TestCase):
    def test_with_none(self):
        self.assertRaises(ValueError, AWSRole, None)

    def test_with_empty_string(self):
        self.assertRaises(ValueError, AWSRole, '')

    def test_with_malformed_string(self):
        self.assertRaises(ValueError, AWSRole, 'arn_noseparator_provider')

    def test_with_missing_arn_string(self):
        self.assertRaises(ValueError, AWSRole, ',provider')

    def test_with_missing_provider_string(self):
        self.assertRaises(ValueError, AWSRole, 'arn:aws:iam::123456789012:role/path/role-name,')

    def test_with_well_formed_string(self):
        role = AWSRole('arn:aws:iam::123456789012:role/path/role-name,provider')
        self.assertEqual(role.account, '123456789012')
        self.assertEqual(role.arn, 'arn:aws:iam::123456789012:role/path/role-name')
        self.assertEqual(role.name, 'role-name')
        self.assertEqual(role.profile, '123456789012.role-name')
        self.assertEqual(role.provider, 'provider')


if __name__ == '__main__':
    unittest.main()
