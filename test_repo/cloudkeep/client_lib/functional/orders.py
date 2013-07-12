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

from test_repo.cloudkeep.client_lib.fixtures import OrdersFixture
from barbicanclient.common.exceptions import ClientException
from cafe.drivers.unittest.decorators import tags


class OrdersAPI(OrdersFixture):

    @unittest2.skip
    @tags(type='positive')
    def test_cl_create_order_w_only_mime_type(self):
        """Covers creating order with only required fields. In this case,
        only mime type is required.
        """
        try:
            order = self.cl_behaviors.create_order(
                mime_type=self.config.mime_type)
        except ClientException, error:
            self.fail("Creation failed with ClientException: "
                      "{0}".format(error))

        resp = self.barb_client.get_order(order.id)
        self.assertEqual(resp.status_code, 200,
                         'Barbican returned bad status code')

    @tags(type='negative')
    def test_cl_create_order_w_null_values(self):
        """Covers creating order with all null values. Should raise a
        ClientException.
        """
        self.assertRaises(ClientException, self.cl_behaviors.create_order)

    @tags(type='positive')
    def test_cl_create_order_w_null_name(self):
        """Covers creating order without a null name."""
        order = self.cl_behaviors.create_order(
            name=None,
            mime_type=self.config.mime_type,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        self.assertIsNotNone(order)

    @tags(type='positive')
    def test_cl_create_order_w_null_name_checking_name(self):
        """Covers creating order with a null name, checking that the name
        matches the order ID.
        """
        order = self.cl_behaviors.create_order(
            name=None,
            mime_type=self.config.mime_type,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        secret_id = self.cl_behaviors.get_id_from_ref(order.secret_ref)
        self.assertEqual(order.secret['name'], secret_id,
                         "Name did not match order ID")

    @tags(type='positive')
    def test_cl_create_order_w_empty_name(self):
        """Covers creating order without an empty name."""
        order = self.cl_behaviors.create_order(
            name='',
            mime_type=self.config.mime_type,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        self.assertIsNotNone(order)

    @tags(type='positive')
    def test_cl_create_order_w_empty_name_checking_name(self):
        """Covers creating order with an empty name, checking that the name
        matches the order ID."""
        order = self.cl_behaviors.create_order(
            name='',
            mime_type=self.config.mime_type,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        secret_id = self.cl_behaviors.get_id_from_ref(order.secret_ref)
        self.assertEqual(order.secret['name'], secret_id,
                         "Name did not match order ID")

    @tags(type='negative')
    def test_cl_create_order_w_invalid_mime_type(self):
        """Covers creating order with an invalid mime type.
        Should raise a ClientException.
        """
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_order_overriding_cfg,
                          mime_type='crypto/boom')

    @tags(type='negative')
    def test_cl_create_order_w_invalid_bit_length(self):
        """Covers creating order with a bit length that is not an integer.
        Should raise a ClientException.
        """
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_order_overriding_cfg,
                          bit_length='not-an-int')

    @tags(type='negative')
    def test_cl_create_order_w_negative_bit_length(self):
        """Covers creating order with a negative bit length.
        Should raise a ClientException.
        """
        self.assertRaises(ClientException,
                          self.cl_behaviors.create_order_overriding_cfg,
                          bit_length=-1)

    @tags(type='positive')
    def test_cl_create_order_checking_metadata(self):
        """Covers creating order and checking metadata of secret created.
        Assumes that order status is active and not pending.
        """
        order = self.cl_behaviors.create_order_from_config()
        secret = order.secret

        self.assertEqual(secret['name'], self.config.name)
        self.assertEqual(secret['mime_type'], self.config.mime_type)
        self.assertEqual(secret['cypher_type'], self.config.cypher_type)
        self.assertEqual(secret['algorithm'], self.config.algorithm)
        self.assertEqual(secret['bit_length'], self.config.bit_length)

    @tags(type='negative')
    def test_cl_delete_nonexistent_order_by_href(self):
        """Covers deleting an order that does not exist by href.
        Should raise a ClientException.
        """
        self.assertRaises(ClientException,
                          self.cl_behaviors.delete_order,
                          'not-an-href')

    @tags(type='negative')
    def test_cl_delete_nonexistent_order_by_id(self):
        """Covers deleting an order that does not exist by id.
        Should raise a ClientException.
        """
        self.assertRaises(ClientException,
                          self.cl_behaviors.delete_order_by_id,
                          'not-an-id')

    @tags(type='negative')
    def test_def_get_nonexistent_order_by_href(self):
        """Covers getting an order that does not exist by href.
        Should raise a ClientException.
        """
        self.assertRaises(ClientException,
                          self.cl_client.get_order,
                          'not-an-href')

    @tags(type='negative')
    def test_cl_get_nonexistent_order_by_id(self):
        """Covers deleting an order that does not exist by id.
        Should raise a ClientException.
        """
        self.assertRaises(ClientException,
                          self.cl_client.get_order_by_id,
                          'not-an-id')

    @tags(type='positive')
    def test_cl_get_order_by_href_checking_metadata(self):
        """Covers getting an order by href and checking the secret
        metadata. Assumes that order status is active and not pending.
        """
        resp = self.barb_behaviors.create_order_from_config()
        self.assertEqual(resp['status_code'], 202,
                         'Barbican returned bad status code')

        order = self.cl_client.get_order(resp['order_ref'])
        secret_metadata = order.secret

        self.assertEqual(secret_metadata['name'], self.config.name)
        self.assertEqual(secret_metadata['mime_type'], self.config.mime_type)
        self.assertEqual(secret_metadata['algorithm'], self.config.algorithm)
        self.assertEqual(secret_metadata['bit_length'], self.config.bit_length)
        self.assertEqual(secret_metadata['cypher_type'],
                         self.config.cypher_type)

    @tags(type='positive')
    def test_cl_get_order_by_id_checking_metadata(self):
        """Covers getting an order by id and checking the secret
        metadata. Compares to the values of the initial creation.
        Assumes that order status is active and not pending.
        """
        resp = self.barb_behaviors.create_order_from_config()
        self.assertEqual(resp['status_code'], 202,
                         'Barbican returned bad status code')

        order = self.cl_client.get_order_by_id(resp['order_id'])
        secret_metadata = order.secret

        self.assertEqual(secret_metadata['name'], self.config.name)
        self.assertEqual(secret_metadata['mime_type'], self.config.mime_type)
        self.assertEqual(secret_metadata['algorithm'], self.config.algorithm)
        self.assertEqual(secret_metadata['bit_length'], self.config.bit_length)
        self.assertEqual(secret_metadata['cypher_type'],
                         self.config.cypher_type)

    @tags(type='positive')
    def test_cl_get_order_w_expiration_by_href(self):
        """Covers getting an order that created a secret with an expiration
        by href. Assumes that order status is active and not pending.
        """
        resp = self.barb_behaviors.create_order_from_config(
            use_expiration=True)
        self.assertEqual(resp['status_code'], 202,
                         'Barbican returned bad status code')

        order_ref = resp['order_ref']
        order = self.cl_client.get_order(href=order_ref)
        secret = order.secret
        self.assertIsNotNone(secret['expiration'])

    @tags(type='positive')
    def test_cl_get_order_w_expiration_by_id(self):
        """Covers getting an order that created a secret with an expiration
        by id. Assumes that order status is active and not pending.
        """
        resp = self.barb_behaviors.create_order_from_config(
            use_expiration=True)
        self.assertEqual(resp['status_code'], 202,
                         'Barbican returned bad status code')

        order_id = resp['order_id']
        order = self.cl_client.get_order_by_id(order_id=order_id)
        secret = order.secret
        self.assertIsNotNone(secret['expiration'])

    @tags(type='positive')
    def test_cl_order_get_secret_checking_metadata(self):
        """Covers getting a secret using the Order object function and
        checking the metadata of the secret. Assumes that order status
        is active and not pending.
        """
        resp = self.barb_behaviors.create_order_from_config()
        self.assertEqual(resp['status_code'], 202,
                         'Barbican returned bad status code')

        order = self.cl_client.get_order_by_id(resp['order_id'])
        secret = order.get_secret()

        self.assertEqual(secret.status, 'ACTIVE')
        self.assertEqual(secret.name, self.config.name)
        self.assertEqual(secret.mime_type, self.config.mime_type)
        self.assertEqual(secret.algorithm, self.config.algorithm)
        self.assertEqual(secret.bit_length, self.config.bit_length)
        self.assertEqual(secret.cypher_type, self.config.cypher_type)

    @tags(type='positive')
    def test_cl_list_orders_limit_and_offset(self):
        """Covers using the limit and offset attribute of listing orders."""
        # Create order pool
        for count in range(20):
            resp = self.barb_behaviors.create_order_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 202,
                             'Barbican returned bad status code')

        # First set of orders
        tuple = self.cl_client.list_orders(limit=10, offset=0)
        order_group1 = tuple[0]

        # Second set of orders
        tuple = self.cl_client.list_orders(limit=10, offset=10)
        order_group2 = tuple[0]

        order_ids1 = [order.id for order in order_group1]
        order_ids2 = [order.id for order in order_group2]

        duplicates = [order_id for order_id in order_ids1
                      if order_id in order_ids2]

        self.assertEqual(len(order_group1), 10)
        self.assertEqual(len(order_group2), 10)
        self.assertEqual(len(duplicates), 0,
                         'Using offset didn\'t return unique orders')

    @tags(type='positive')
    def test_cl_list_orders_next(self):
        """Covers using next reference for listing orders."""
        # Create order pool
        for count in range(20):
            resp = self.barb_behaviors.create_order_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 202,
                             'Barbican returned bad status code')

        # First set of orders
        order_group1, prev_ref, next_ref = self.cl_client.list_orders(
            limit=10, offset=0)

        # Next set of orders
        list_tuple = self.cl_client.list_orders_by_href(href=next_ref)
        order_group2 = list_tuple[0]

        order_ids1 = [order.id for order in order_group1]
        order_ids2 = [order.id for order in order_group2]

        duplicates = [order_id for order_id in order_ids1
                      if order_id in order_ids2]

        self.assertEqual(len(duplicates), 0,
                         'Using next reference didn\'t return unique orders')
        self.assertEqual(len(order_group2), 10)

    @tags(type='positive')
    def test_cl_list_orders_previous(self):
        """Covers using next reference for listing orders."""
        # Create order pool
        for count in range(20):
            resp = self.barb_behaviors.create_order_from_config(
                use_expiration=False)
            self.assertEqual(resp['status_code'], 202,
                             'Barbican returned bad status code')

        # First set of orders
        order_group1, prev_ref, next_ref = self.cl_client.list_orders(
            limit=10, offset=10)

        # Previous set of orders
        list_tuple = self.cl_client.list_orders_by_href(href=prev_ref)
        order_group2 = list_tuple[0]

        order_ids1 = [order.id for order in order_group1]
        order_ids2 = [order.id for order in order_group2]

        duplicates = [order_id for order_id in order_ids1
                      if order_id in order_ids2]

        self.assertEqual(len(duplicates), 0,
                         'Using next reference didn\'t return unique orders')
        self.assertEqual(len(order_group2), 10)
