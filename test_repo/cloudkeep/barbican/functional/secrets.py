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
import unittest2
from test_repo.cloudkeep.barbican.fixtures import SecretsFixture


class SecretsAPI(SecretsFixture):

    def test_secret_with_plain_text_deletion(self):
        """ Reported in Barbican GitHub Issue #77 """
        resp = self.behaviors.create_secret_from_config(use_expiration=False,
                                                        use_plain_text=True)
        self.assertEqual(resp['status_code'], 201)

        del_resp = self.behaviors.delete_secret(resp['secret_id'])
        self.assertEqual(del_resp.status_code, 200)

    def test_find_a_single_secret_via_paging(self):
        """ Reported in Barbican GitHub Issue #81 """
        resp = self.behaviors.create_secret_from_config(use_expiration=False)
        for count in range(1, 11):
            self.behaviors.create_secret_from_config(use_expiration=False)
        secret = self.behaviors.find_secret(resp['secret_id'])
        self.assertIsNotNone(secret, 'Couldn\'t find created secret')

    def test_creating_secret_w_bit_length_str(self):
        resps = self.behaviors.create_and_check_secret(bit_length=512)
        secret = resps['get_resp'].entity
        self.assertEqual(resps['get_resp'].status_code, 200)
        self.assertIs(type(secret.bit_length), int)
        self.assertEqual(secret.bit_length, 512)

    def test_creating_w_null_entries(self):
        """ Reported in Barbican GitHub Issue #90 """
        resp = self.behaviors.create_secret()
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    def test_creating_w_empty_name(self):
        resp = self.behaviors.create_secret(name=None,
                                            mime_type=self.config.mime_type)
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    def test_creating_w_empty_mime_type(self):
        resps = self.behaviors.create_and_check_secret(mime_type='')
        self.assertEqual(resps['create_resp']['status_code'], 400,
                         'Should have failed with 400')

    def test_creating_w_empty_secret(self):
        resps = self.behaviors.create_and_check_secret(plain_text='')
        self.assertEqual(resps['create_resp']['status_code'], 400,
                         'Should have failed with 400')

    def test_creating_w_oversized_secret(self):
        """
        Current size limit is 10k bytes. Beyond that it should return 413
        """
        data = bytearray().zfill(10001)

        resps = self.behaviors.create_and_check_secret(plain_text=str(data))
        self.assertEqual(resps['create_resp']['status_code'], 413,
                         'Should have failed with 413')

    def test_creating_w_invalid_mime_type(self):
        resps = self.behaviors.create_and_check_secret(mime_type='crypto/boom')
        self.assertEqual(resps['create_resp']['status_code'], 400,
                         'Should have failed with 400')

    def test_getting_secret_that_doesnt_exist(self):
        resp = self.client.get_secret('not_a_uuid')
        self.assertEqual(resp.status_code, 404, 'Should have failed with 404')

    def test_getting_secret_data_w_invalid_mime_type(self):
        resp = self.behaviors.create_secret_from_config(use_expiration=False)
        resp = self.client.get_secret(resp['secret_id'], mime_type='i/m')
        self.assertEqual(resp.status_code, 406, 'Should have failed with 406')

    def test_creating_w_plain_text_as_array(self):
        resps = self.behaviors.create_and_check_secret(plain_text=['boom'])
        self.assertEqual(resps['create_resp']['status_code'], 400,
                         'Should have failed with 400')
