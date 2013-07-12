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
from datetime import datetime, timedelta
from uuid import uuid4
import unittest2

from test_repo.cloudkeep.barbican.fixtures import SecretsFixture
from cafe.drivers.unittest.decorators import tags
from cloudcafe.common.tools import randomstring


class SecretsAPI(SecretsFixture):

    def check_expiration_iso8601_timezone(self, timezone, offset):
        one_day_ahead = (datetime.today() + timedelta(days=1))
        timestamp = '{time}{timezone}'.format(
            time=one_day_ahead,
            timezone=timezone)

        resp = self.behaviors.create_secret_overriding_cfg(
            expiration=timestamp)
        self.assertEqual(resp['status_code'], 201)

        secret = self.client.get_secret(resp['secret_id']).entity
        exp = datetime.strptime(secret.expiration, '%Y-%m-%dT%H:%M:%S.%f')
        self.assertEqual(exp, one_day_ahead + timedelta(hours=offset),
                         'Response didn\'t return the expected time')

    def check_invalid_expiration_timezone(self, timezone):
        timestamp = '{time}{timezone}'.format(
            time=(datetime.today() + timedelta(days=1)),
            timezone=timezone)

        resp = self.behaviors.create_secret_overriding_cfg(
            expiration=timestamp)
        self.assertEqual(resp['status_code'], 400)

    @tags(type='positive')
    def test_secret_with_plain_text_deletion(self):
        """ Covers case where the system fails to delete a secret if it
        contains a set "plain_text" field.
        - Reported in Barbican GitHub Issue #77
        """
        resp = self.behaviors.create_secret_from_config(use_expiration=False,
                                                        use_plain_text=True)
        self.assertEqual(resp['status_code'], 201)

        del_resp = self.behaviors.delete_secret(resp['secret_id'])
        self.assertEqual(del_resp.status_code, 200)

    @tags(type='positive')
    def test_create_secret_with_long_expiration_timezone(self):
        """ Covers case of a timezone being added to the expiration.
        The server should convert it into zulu time.
        - Reported in Barbican GitHub Issue #131
        """
        self.check_expiration_iso8601_timezone('-05:00', 5)
        self.check_expiration_iso8601_timezone('+05:00', -5)

    @unittest2.skip('Issue #135')
    @tags(type='positive')
    def test_create_secret_with_short_expiration_timezone(self):
        """ Covers case of a timezone being added to the expiration.
        The server should convert it into zulu time.
        - Reported in Barbican GitHub Issue #135
        """
        self.check_expiration_iso8601_timezone('-01', 1)
        self.check_expiration_iso8601_timezone('+01', -1)

    @unittest2.skip('Issue #134')
    @tags(type='negative')
    def test_create_secret_with_bad_expiration_timezone(self):
        """ Covers case of a malformed timezone being added to the expiration.
        - Reported in Barbican GitHub Issue #134
        """
        self.check_invalid_expiration_timezone('-5:00')

    @tags(type='positive')
    def test_find_a_single_secret_via_paging(self):
        """ Covers case where when you attempt to retrieve a list of secrets,
        if the limit is set higher than 8, the next attribute in the response
        is not available.
        - Reported in Barbican GitHub Issue #81
        """
        resp = self.behaviors.create_secret_from_config(use_expiration=False)
        for count in range(1, 11):
            self.behaviors.create_secret_from_config(use_expiration=False)
        secret = self.behaviors.find_secret(resp['secret_id'])
        self.assertIsNotNone(secret, 'Couldn\'t find created secret')

    @tags(type='positive')
    def test_creating_secret_w_bit_length(self):
        """ Covers creating secret with a bit length. """
        resps = self.behaviors.create_and_check_secret(bit_length=512)
        secret = resps['get_resp'].entity
        self.assertEqual(resps['get_resp'].status_code, 200)
        self.assertIs(type(secret.bit_length), int)
        self.assertEqual(secret.bit_length, 512)

    @tags(type='negative')
    def test_creating_w_null_entries(self):
        """ Covers case when you push a secret full of nulls. This should
        return a 400.
        - Reported in Barbican GitHub Issue #90
        """
        resp = self.behaviors.create_secret()
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_creating_w_empty_entries(self):
        """ Covers case of creating a secret with empty Strings for all
        entries. Should return a 400.
        """
        resp = self.behaviors.create_secret(name='',
                                            expiration='',
                                            algorithm='',
                                            cypher_type='',
                                            plain_text='',
                                            mime_type='')
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='positive')
    def test_creating_w_empty_name(self):
        """ When a test is created with an empty or null name attribute, the
         system should return the secret's UUID on a get
         - Reported in Barbican GitHub Issue #89
        """
        c_resp = self.behaviors.create_secret(name='',
                                              mime_type=self.config.mime_type)

        get_resp = self.client.get_secret(secret_id=c_resp['secret_id'])
        self.assertEqual(get_resp.entity.name,
                         c_resp['secret_id'],
                         'name doesn\'t match UUID of secret')

    @tags(type='positive')
    def test_creating_w_null_name(self):
        """ When a test is created with an empty or null name attribute, the
         system should return the secret's UUID on a get
         - Reported in Barbican GitHub Issue #89
        """
        c_resp = self.behaviors.create_secret(name=None,
                                              mime_type=self.config.mime_type)

        get_resp = self.client.get_secret(secret_id=c_resp['secret_id'])
        self.assertEqual(get_resp.entity.name,
                         c_resp['secret_id'],
                         'name doesn\'t match UUID of secret')

    @tags(type='negative')
    def test_creating_w_empty_mime_type(self):
        resp = self.behaviors.create_secret(mime_type='')
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_creating_w_null_mime_type(self):
        resp = self.behaviors.create_secret(
            name=self.config.name,
            plain_text=self.config.plain_text,
            algorithm=self.config.algorithm,
            cypher_type=self.config.cypher_type,
            bit_length=self.config.bit_length,
            mime_type=None
        )
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_creating_w_empty_secret(self):
        resp = self.behaviors.create_secret(mime_type=self.config.mime_type,
                                            plain_text='')
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_creating_w_oversized_secret(self):
        """
        Current size limit is 10k bytes. Beyond that it should return 413
        """
        data = bytearray().zfill(10001)

        resps = self.behaviors.create_and_check_secret(plain_text=str(data))
        self.assertEqual(resps['create_resp']['status_code'], 413,
                         'Should have failed with 413')

    @tags(type='negative')
    def test_creating_w_invalid_mime_type(self):
        resps = self.behaviors.create_and_check_secret(mime_type='crypto/boom')
        self.assertEqual(resps['create_resp']['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_getting_secret_that_doesnt_exist(self):
        resp = self.client.get_secret('not_a_uuid')
        self.assertEqual(resp.status_code, 404, 'Should have failed with 404')

    @tags(type='negative')
    def test_getting_secret_data_w_invalid_mime_type(self):
        resp = self.behaviors.create_secret_from_config(use_expiration=False)
        resp = self.client.get_secret(resp['secret_id'], mime_type='i/m')
        self.assertEqual(resp.status_code, 406, 'Should have failed with 406')

    @tags(type='negative')
    def test_creating_w_plain_text_as_array(self):
        resps = self.behaviors.create_and_check_secret(plain_text=['boom'])
        self.assertEqual(resps['create_resp']['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='positive')
    def test_paging_limit_and_offset(self):
        """
        Covers using paging limit and offset attributes when getting
        a list of secrets.
        """
        # Create secret pool
        for count in range(20):
            resp = self.behaviors.create_secret_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 201,
                             'Returned bad status code')

        # First set of secrets
        resp = self.client.get_secrets(limit=10, offset=0)
        self.assertEqual(resp.status_code, 200, 'Returned bad status code')
        sec_group1 = resp.entity

        # Second set of secrets
        resp = self.client.get_secrets(limit=10, offset=10)
        self.assertEqual(resp.status_code, 200, 'Returned bad status code')
        sec_group2 = resp.entity

        duplicates = [secret for secret in sec_group1.secrets
                      if secret in sec_group2.secrets]

        self.assertEqual(len(sec_group1.secrets), 10)
        self.assertEqual(len(sec_group2.secrets), 10)
        self.assertEqual(len(duplicates), 0,
                         'Using offset didn\'t return unique secrets')

    @tags(type='positive')
    def test_secret_paging_next_option(self):
        """Covers getting a list of secrets and using the next
        reference.
        """
        # Create secret pool
        for count in range(170):
            resp = self.behaviors.create_secret_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 201,
                             'Returned bad status code')

        # First set of secrets
        resp = self.client.get_secrets(limit=25, offset=115)
        self.assertEqual(resp.status_code, 200, 'Returned bad status code')
        sec_group1 = resp.entity
        self.assertEqual(len(sec_group1.secrets), 25,
                         'Returned wrong number of secrets')
        next_ref = sec_group1.next
        self.assertIsNotNone(next_ref)

        #Next set of secrets
        resp = self.client.get_secrets(ref=next_ref)
        self.assertEqual(resp.status_code, 200, 'Returned bad status code')
        sec_group2 = resp.entity
        self.assertEqual(len(sec_group2.secrets), 25)

        duplicates = [secret for secret in sec_group1.secrets
                      if secret in sec_group2.secrets]

        self.assertEqual(len(duplicates), 0,
                         'Using next reference didn\'t return unique secrets')

    @tags(type='positive')
    def test_secret_paging_previous_option(self):
        """Covers getting a list of secrets and using the previous
        reference.
        """
        # Create secret pool
        for count in range(170):
            resp = self.behaviors.create_secret_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 201,
                             'Returned bad status code')

        resp = self.client.get_secrets(limit=25, offset=115)
        self.assertEqual(resp.status_code, 200, 'Returned bad status code')

        sec_group1 = resp.entity
        self.assertEqual(len(sec_group1.secrets), 25,
                         'Returned wrong number of secrets')
        previous_ref = sec_group1.previous
        self.assertIsNotNone(previous_ref)

        #Previous set of secrets
        resp = self.client.get_secrets(ref=previous_ref)
        self.assertEqual(resp.status_code, 200, 'Returned bad status code')
        sec_group2 = resp.entity
        self.assertEqual(len(sec_group2.secrets), 25)

        duplicates = [secret for secret in sec_group1.secrets
                      if secret in sec_group2.secrets]

        self.assertEqual(len(duplicates), 0, 'Using previous reference '
                                             'didn\'t return unique secrets')

    @tags(type='negative')
    def test_putting_secret_that_doesnt_exist(self):
        """ Covers case of putting secret information to a non-existent
        secret. Should return 404.
        """
        resp = self.client.add_secret_plain_text(
            secret_id='not_a_uuid',
            mime_type=self.config.mime_type,
            plain_text='testing putting to non-existent secret')
        self.assertEqual(resp.status_code, 404,
                         'Should have failed with 404')

    @tags(type='negative')
    def test_putting_w_invalid_mime_type(self):
        """ Covers case of putting secret information with an
        invalid mime-type. Should return 400.
        """
        resp = self.behaviors.create_secret(mime_type=self.config.mime_type)
        put_resp = self.client.add_secret_plain_text(
            secret_id=resp['secret_id'],
            mime_type='crypto/boom',
            plain_text='testing putting with invalid mime type')
        self.assertEqual(put_resp.status_code, 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_putting_secret_w_data_already(self):
        """ Covers case of putting secret information to a secret that already
        has encrypted data associated with it. Should return 409.
        """
        resp = self.behaviors.create_secret_from_config(use_expiration=False)
        put_resp = self.client.add_secret_plain_text(
            secret_id=resp['secret_id'],
            mime_type=self.config.mime_type,
            plain_text='testing putting to a secret that already has data')
        self.assertEqual(put_resp.status_code, 409,
                         'Should have failed with 409')

    @tags(type='negative')
    def test_putting_w_empty_data(self):
        """
        Covers case of putting empty String to a secret. Should return 400.
        """
        resp = self.behaviors.create_secret(mime_type=self.config.mime_type)
        put_resp = self.client.add_secret_plain_text(
            secret_id=resp['secret_id'],
            mime_type=self.config.mime_type,
            plain_text='')
        self.assertEqual(put_resp.status_code, 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_putting_w_null_data(self):
        """
        Covers case of putting null String to a secret. Should return 400.
        """
        resp = self.behaviors.create_secret(mime_type=self.config.mime_type)
        put_resp = self.client.add_secret_plain_text(
            secret_id=resp['secret_id'],
            mime_type=self.config.mime_type,
            plain_text=None)
        self.assertEqual(put_resp.status_code, 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_putting_w_oversized_data(self):
        """ Covers case of putting secret data that is beyond size limit.
        Current size limit is 10k bytes. Beyond that it should return 413.
        """
        data = bytearray().zfill(10001)
        resp = self.behaviors.create_secret(mime_type=self.config.mime_type)
        put_resp = self.client.add_secret_plain_text(
            secret_id=resp['secret_id'],
            mime_type=self.config.mime_type,
            plain_text=str(data))
        self.assertEqual(put_resp.status_code, 413,
                         'Should have failed with 413')

    @tags(type='negative')
    def test_deleting_secret_that_doesnt_exist(self):
        """
        Covers case of deleting a non-existent secret. Should return 404.
        """
        resp = self.behaviors.delete_secret(secret_id='not_a_uuid')
        self.assertEqual(resp.status_code, 404, 'Should have failed with 404')

    @tags(type='negative')
    def test_creating_secret_w_invalid_expiration(self):
        """
        Covers creating secret with expiration that has already passed.
        Should return 400.
        """
        resp = self.behaviors.create_secret_overriding_cfg(
            expiration='2000-01-10T14:58:52.546795')
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='positive')
    def test_checking_content_types_when_data(self):
        """ Covers checking that content types attribute is shown when secret
        has encrypted data associated with it.
        """
        resps = self.behaviors.create_and_check_secret()
        secret = resps['get_resp'].entity
        self.assertIsNotNone(secret.content_types,
                             'Should not have had content types')

    @tags(type='positive')
    def test_checking_no_content_types_when_no_data(self):
        """ Covers checking that the content types attribute is not shown if
        the secret does not have encrypted data associated with it.
        """
        create_resp = self.behaviors.create_secret(
            mime_type=self.config.mime_type)
        secret_id = create_resp['secret_id']
        resp = self.client.get_secret(secret_id=secret_id)
        secret = resp.entity
        self.assertIsNone(secret.content_types,
                          'Should have had content types')

    @tags(type='negative')
    def test_creating_secret_w_invalid_bit_length(self):
        """ Cover case of creating a secret with a bit length that is not
        an integer. Should return 400.
        """
        resp = self.behaviors.create_secret_overriding_cfg(
            bit_length='not-an-int')
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='negative')
    def test_creating_secret_w_negative_bit_length(self):
        """ Covers case of creating a secret with a bit length
        that is negative. Should return 400.
        """
        resp = self.behaviors.create_secret_overriding_cfg(
            bit_length=-1)
        self.assertEqual(resp['status_code'], 400,
                         'Should have failed with 400')

    @tags(type='positive')
    def test_creating_secret_w_only_mime_type(self):
        """ Covers creating secret with only required fields. In this case,
        only mime type is required.
        """
        resp = self.behaviors.create_secret(mime_type=self.config.mime_type)
        self.assertEqual(resp['status_code'], 201, 'Returned bad status code')

    @unittest2.skip('Issue #171')
    @tags(type='negative')
    def test_secret_paging_w_invalid_parameters(self):
        """ Covers listing secrets with invalid limit and offset parameters.
        Should return 400.
        - Reported in Barbican GitHub Issue #171
        """
        self.behaviors.create_secret_from_config(use_expiration=False)
        resp = self.client.get_secrets(limit='not-an-int', offset='not-an-int')
        self.assertEqual(resp.status_code, 400, 'Should have failed with 400')

    @tags(type='positive')
    def test_creating_secret_w_alphanumeric_name(self):
        """Covers case of creating secret with an alphanumeric name."""
        name = randomstring.get_random_string(prefix='1a2b')
        resps = self.behaviors.create_and_check_secret(name=name)
        self.assertEqual(resps['create_resp']['status_code'], 201,
                         'Returned bad status code')

        secret = resps['get_resp'].entity
        self.assertEqual(secret.name, name, 'Secret name is not correct')

    @tags(type='positive')
    def test_creating_secret_w_punctuation_in_name(self):
        """Covers case of creating a secret with miscellaneous punctuation and
        symbols in the name.
        """
        name = '~!@#$%^&*()_+`-={}[]|:;<>,.?"'
        resps = self.behaviors.create_and_check_secret(name=name)
        self.assertEqual(resps['create_resp']['status_code'],201,
                         'Returned bad status code')

        secret = resps['get_resp'].entity
        self.assertEqual(secret.name, name, 'Secret name is not correct')

    @tags(type='positive')
    def test_creating_secret_w_uuid_as_name(self):
        """Covers case of creating a secret with a random uuid as the name."""
        uuid = str(uuid4())
        resps = self.behaviors.create_and_check_secret(name=uuid)
        self.assertEqual(resps['create_resp']['status_code'], 201,
                         'Returned bad status code')

        secret = resps['get_resp'].entity
        self.assertEqual(secret.name, uuid, 'Secret name is not correct')

    @tags(type='positive')
    def test_create_secret_w_name_of_len_255(self):
        """Covers case of creating a secret with a 225 character name."""
        name = randomstring.get_random_string(size=225)
        resps = self.behaviors.create_and_check_secret(name=name)
        self.assertEqual(resps['create_resp']['status_code'], 201,
                         'Returned bad status code')

        secret = resps['get_resp'].entity
        self.assertEqual(secret.name, name, 'Secret name is not correct')

    @tags(type='positive')
    def test_creating_secret_w_128_bit_length(self):
        """Covers case of creating a secret with a 128 bit length."""
        resps = self.behaviors.create_and_check_secret(bit_length=128)
        self.assertEqual(resps['create_resp']['status_code'], 201,
                         'Returned bad status code')

        secret = resps['get_resp'].entity
        self.assertEqual(resps['get_resp'].status_code, 200)
        self.assertIs(type(secret.bit_length), int)
        self.assertEqual(secret.bit_length, 128)

    @tags(type='positive')
    def test_creating_secret_w_192_bit_length(self):
        """Covers case of creating a secret with a 192 bit length."""
        resps = self.behaviors.create_and_check_secret(bit_length=192)
        self.assertEqual(resps['create_resp']['status_code'], 201,
                         'Returned bad status code')

        secret = resps['get_resp'].entity
        self.assertEqual(resps['get_resp'].status_code, 200)
        self.assertIs(type(secret.bit_length), int)
        self.assertEqual(secret.bit_length, 192)

    @tags(type='positive')
    def test_creating_secret_w_256_bit_length(self):
        """Covers case of creating a secret with a 256 bit length."""
        resps = self.behaviors.create_and_check_secret(bit_length=256)
        self.assertEqual(resps['create_resp']['status_code'], 201,
                         'Returned bad status code')

        secret = resps['get_resp'].entity
        self.assertEqual(resps['get_resp'].status_code, 200)
        self.assertIs(type(secret.bit_length), int)
        self.assertEqual(secret.bit_length, 256)

    @tags(type='positive')
    def test_creating_secret_w_aes_algorithm(self):
        """Covers case of creating a secret with an aes algorithm."""
        resp = self.behaviors.create_secret_overriding_cfg(algorithm='aes')
        self.assertEqual(resp['status_code'], 201, 'Returned bad status code')

    @tags(type='positive')
    def test_creating_secret_w_cbc_cypher_type(self):
        """Covers case of creating a secret with a cbc cypher type."""
        resp = self.behaviors.create_secret_overriding_cfg(cypher_type='cbc')
        self.assertEqual(resp['status_code'], 201, 'Returned bad status code')

    @tags(type='positive')
    def test_secret_hostname_response(self):
        """Covers case of checking that hostname of secret_ref is the same
        as the configured hostname.
        - Reported in Barbican GitHub Issue #182
        """
        resp = self.behaviors.create_secret_from_config()
        if not resp['secret_ref'].startswith(self.cloudkeep.base_url):
            self.fail('Incorrect hostname in response ref.')

    @tags(type='positive')
    def test_creating_secret_w_text_plain_mime_type(self):
        """Covers case of creating a secret with text/plain as mime type.
        """
        resp = self.behaviors.create_secret_overriding_cfg(
            mime_type='text/plain')
        self.assertEqual(resp['status_code'], 201, 'Returned bad status code')

    @tags(type='positive')
    def test_creating_secret_w_app_octet_mime_type(self):
        """Covers case of creating a secret with text/plain as mime type.
        """
        resp = self.behaviors.create_secret_overriding_cfg(
            mime_type='application/octet-stream')
        self.assertEqual(resp['status_code'], 201, 'Returned bad status code')

    @tags(type='positive')
    def test_creating_secret_w_empty_checking_name(self):
        """ When an secret is created with an empty name attribute, the
        system should return the secret's UUID on a get. Extends coverage of
        test_creating_w_empty_name.
        """
        resp = self.behaviors.create_secret(
            mime_type=self.config.mime_type,
            name="",
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)

        get_resp = self.client.get_secret(resp['secret_id'])
        secret = get_resp.entity
        self.assertEqual(secret.name, secret.get_id(),
                         'Name did not match secret\'s UUID')

    @tags(type='positive')
    def test_creating_secret_wout_name_checking_name(self):
        """ When a secret is created with a null name attribute, the
        system should return the secret's UUID on a get. Extends coverage of
        test_creating_w_null_name.
        """
        resp = self.behaviors.create_secret(
            mime_type=self.config.mime_type,
            name=None,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)

        get_resp = self.client.get_secret(resp['secret_id'])
        secret = get_resp.entity
        self.assertEqual(secret.name, secret.get_id(),
                         'Name did not match secret\'s UUID')

    @tags(type='positive')
    def test_secret_paging_max_limit(self):
        """Covers case of listing secrets with a limit more than the current
        maximum of 100.
        """
        # Create secret pool
        for count in range(101):
            resp = self.behaviors.create_secret_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 201,
                             'Returned bad status code')

        resp = self.client.get_secrets(limit=101, offset=0)
        self.assertEqual(resp.status_code, 200, 'Returned bad status code')

        sec_group = resp.entity
        self.assertEqual(len(sec_group.secrets), 100,
                         'Returned wrong number of secrets')

    @tags(type='positive')
    def test_secret_paging_limit(self):
        """Covers listing secrets with limit attribute from limits
        of 2 to 50.
        """
        # Create secret pool
        for count in range(50):
            resp = self.behaviors.create_secret_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 201,
                             'Returned bad status code')

        for limit in range(2, 50):
            resp = self.client.get_secrets(limit=limit, offset=0)
            self.assertEqual(resp.status_code, 200, 'Returned bad status code')

            sec_group = resp.entity
            self.assertEqual(len(sec_group.secrets), limit,
                             'Returned wrong number of secrets')

    @tags(type='positive')
    def test_secret_paging_offset(self):
        """Covers listing secrets with offset attribute from offsets
        of 2 to 50.
        """
        # Create secret pool
        for count in range(55):
            resp = self.behaviors.create_secret_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 201,
                             'Returned bad status code')

        # Covers offsets between 1 and 50
        for offset in range(1, 49):
            resp = self.client.get_secrets(limit=2, offset=offset)
            self.assertEqual(resp.status_code, 200, 'Returned bad status code')
            sec_group1 = resp.entity
            self.assertEqual(len(sec_group1.secrets), 2)
            previous_ref1 = sec_group1.previous
            self.assertIsNotNone(previous_ref1)
            next_ref1 = sec_group1.next
            self.assertIsNotNone(next_ref1)

            resp = self.client.get_secrets(limit=2, offset=offset + 2)
            self.assertEqual(resp.status_code, 200, 'Returned bad status code')
            sec_group2 = resp.entity
            self.assertEqual(len(sec_group2.secrets), 2)
            previous_ref2 = sec_group2.previous
            self.assertIsNotNone(previous_ref2)
            next_ref2 = sec_group2.next
            self.assertIsNotNone(next_ref2)

            duplicates = [secret for secret in sec_group1.secrets
                          if secret in sec_group2.secrets]

            self.assertEqual(len(duplicates), 0)
