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
from test_repo.cloudkeep.barbican.fixtures import OrdersFixture


class OrdersAPI(OrdersFixture):

    def test_create_order_with_null_mime_type(self):
        """ Covers issue where you attempt to create an order with the
        mime_type attribute set to null and the request appears to fail
        without a status code.
        - Reported in Barbican GitHub Issue #92
        """
        resp = self.behaviors.create_order(
            mime_type=None,
            name=self.config.name,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        self.assertEqual(resp['status_code'], 400, 'Returned bad status code')

    def test_create_order_wout_name(self):
        """ When you attempt to create an order without the name attribute the
         request appears to fail without a status code.
        - Reported in Barbican GitHub Issue #93
        """
        resp = self.behaviors.create_order(
            mime_type=self.config.mime_type,
            name=None,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        self.assertEqual(resp['status_code'], 202, 'Returned bad status code')

    def test_create_order_with_invalid_mime_type(self):
        """ Covers defect where you attempt to create an order with an invalid
         mime_type and the request fails without a status code.
        - Reported in Barbican GitHub Issue #92
        """
        resp = self.behaviors.create_order(
            mime_type="trace/boom",
            name=self.config.name,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        self.assertEqual(resp['status_code'], 400, 'Returned bad status code')

    @unittest2.skip('Issue #140')
    def test_getting_secret_data_as_plain_text(self):
        """ Covers defect where you attempt to get secret information in
        text/plain, and the request fails to decrypt the information.
        - Reported in Barbican GitHub Issue #140
        """
        resps = self.behaviors.create_and_check_order(
            mime_type="text/plain",
            name=self.config.name,
            algorithm=self.config.algorithm,
            bit_length=self.config.bit_length,
            cypher_type=self.config.cypher_type)
        self.assertEqual(resps['get_secret_resp'].status_code, 200, 'Returned bad status code')

    def test_get_order_that_doesnt_exist(self):
        """
        Covers case of getting a non-existent order. Should return 404.
        """
        resp = self.client.get_order('not_an_order')
        self.assertEqual(resp.status_code, 404, 'Should have failed with 404')

    def test_delete_order_that_doesnt_exist(self):
        """
        Covers case of deleting a non-existent order. Should return 404.
        """
        resp = self.client.delete_order('not_an_order')
        self.assertEqual(resp.status_code, 404, 'Should have failed with 404')

    def test_order_paging_limit_and_offset(self):
        """
        Covers testing paging limit and offset attributes when getting orders.
        """
        # Create order pool
        for count in range(1, 20):
            self.behaviors.create_order_from_config()

        # First set of orders
        resp = self.client.get_orders(limit=10, offset=0)
        ord_group1 = resp.entity

        # Second set of orders
        resp = self.client.get_orders(limit=20, offset=10)
        ord_group2 = resp.entity

        duplicates = [order for order in ord_group1.orders
                      if order in ord_group2.orders]

        self.assertEqual(len(ord_group1.orders), 10)
        self.assertGreaterEqual(len(ord_group2.orders), 1)
        self.assertEqual(len(duplicates), 0,
                         'Using offset didn\'t return unique orders.')
