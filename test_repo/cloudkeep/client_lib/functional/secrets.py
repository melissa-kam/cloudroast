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
from test_repo.cloudkeep.client_lib.fixtures import SecretsFixture
from barbicanclient.common.exceptions import ClientException
from datetime import datetime, timedelta


class SecretsAPI(SecretsFixture):

    def test_cl_create_secret_w_null_values(self):
        self.assertRaises(ClientException, self.cl_behaviors.create_secret)

    def test_cl_create_secret_w_null_name(self):
        secret = self.cl_behaviors.create_secret(
            name=None, mime_type=self.config.mime_type)
        self.assertIsNotNone(secret)

    def test_cl_create_secret_w_null_name_checking_name(self):
        secret = self.cl_behaviors.create_secret(
            name=None, mime_type=self.config.mime_type)
        self.assertEqual(secret.name, secret.id,
                         "Name did not match secret ID")

    def test_cl_create_secret_w_empty_secret(self):
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_secret_overriding_cfg,
                          plain_text='')

    def test_cl_create_secret_w_invalid_mime_type(self):
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_secret_overriding_cfg,
                          mime_type='crypto/boom')

    def test_cl_create_secret_w_data_as_array(self):
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_secret_overriding_cfg,
                          plain_text=['boom'])

    def test_cl_create_secret_w_invalid_bit_length(self):
        self.assertRaises(ValueError,
                          self.cl_behaviors.create_secret_overriding_cfg,
                          bit_length='not-an-int')

    def test_cl_create_secret_w_negative_bit_length(self):
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_secret_overriding_cfg,
                          bit_length=-1)

    def test_cl_create_secret_w_oversized_data(self):
        data = bytearray().zfill(10001)
        data = data.decode("utf-8")
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_secret_overriding_cfg,
                          plain_text=data)
