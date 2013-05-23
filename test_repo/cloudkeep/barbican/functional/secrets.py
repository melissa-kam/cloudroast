"""
Copyright 2013 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from test_repo.cloudkeep.barbican.fixtures import SecretsFixture


class SecretsAPI(SecretsFixture):

    def test_secret_with_plain_text_deletion(self):
        # Covers Barbican GitHub #77
        resp = self.behaviors.create_secret_from_config(use_expiration=False,
                                                        use_plain_text=True)
        self.assertEqual(resp['status_code'], 201)

        del_resp = self.behaviors.delete_secret(resp['secret_id'])
        self.assertEqual(del_resp.status_code, 200)

    def test_find_a_single_secret_via_paging(self):
        # Covers Barbican GitHub #81
        resp = self.behaviors.create_secret_from_config(use_expiration=False)
        for count in range(1, 11):
            self.behaviors.create_secret_from_config(use_expiration=False)
        secret = self.behaviors.find_secret(resp['secret_id'])
        self.assertIsNotNone(secret, 'Couldn\'t find created secret')
