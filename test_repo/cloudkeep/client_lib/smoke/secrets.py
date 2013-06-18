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


class SecretsAPI(SecretsFixture):

    def test_create_secret(self):
        resp = self.cl_behaviors.create_and_check_secret()
        self.assertEqual(resp['get_resp'].status_code, 200)

    def test_create_secret_wout_expiration(self):
        secret = self.cl_behaviors.create_secret_from_config(
            use_expiration=False)
        resp = self.client.get_secret(secret.id)
        self.assertEqual(resp.status_code, 200)

    def test_get_secret_by_href(self):
        resp = self.behaviors.create_secret_from_config(
            use_expiration=False)
        self.assertEqual(resp['status_code'], 201)

        secret = self.client_lib.get_secret(resp['secret_ref'])
        self.assertIsNotNone(secret)

    def test_get_secret_by_id(self):
        resp = self.behaviors.create_secret_from_config(
            use_expiration=False)
        self.assertEqual(resp['status_code'], 201)

        secret = self.client_lib.get_secret_by_id(resp['secret_id'])
        self.assertIsNotNone(secret)

    def test_delete_secret_by_href(self):
        resp = self.behaviors.create_secret_from_config(
            use_expiration=False)
        self.assertEqual(resp['status_code'], 201)

        self.client_lib.delete_secret(resp['secret_ref'])

        get_resp = self.client.get_secret(resp['secret_id'])
        self.assertEqual(get_resp.status_code, 404)

    def test_delete_secret_by_id(self):
        resp = self.behaviors.create_secret_from_config(
            use_expiration=False)
        self.assertEqual(resp['status_code'], 201)

        self.client_lib.delete_secret_by_id(resp['secret_id'])

        get_resp = self.client.get_secret(resp['secret_id'])
        self.assertEqual(get_resp.status_code, 404)

    def test_list_secrets(self):
        resp = self.behaviors.create_secret_from_config(use_expiration=False)
        self.assertEqual(resp['status_code'], 201)

        secrets = self.client_lib.list_secrets()
        self.assertGreater(len(secrets), 0)

    def test_create_secret_metadata(self):
        secret = self.cl_behaviors.create_secret_from_config(
            use_expiration=False)

        resp = self.client.get_secret(secret.id)
        metadata = resp.entity

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(metadata.status, 'ACTIVE')
        self.assertEqual(metadata.name, self.config.name)
        self.assertEqual(metadata.cypher_type, self.config.cypher_type)
        self.assertEqual(metadata.algorithm, self.config.algorithm)
        self.assertEqual(metadata.bit_length, self.config.bit_length)

    def test_get_raw_secret_by_href(self):
        resp = self.behaviors.create_secret_from_config(
            use_expiration=False)
        self.assertEqual(resp['status_code'], 201)

        raw_secret = self.client_lib.get_raw_secret(
            resp['secret_ref'], self.config.mime_type)

        self.assertEqual(raw_secret, self.config.plain_text)

    def test_get_raw_secret_by_id(self):
        resp = self.behaviors.create_secret_from_config(
            use_expiration=False)
        self.assertEqual(resp['status_code'], 201)

        raw_secret = self.client_lib.get_raw_secret_by_id(
            resp['secret_id'], self.config.mime_type)

        self.assertEqual(raw_secret, self.config.plain_text)
