"""
Copyright 2015 Rackspace

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

import time

from cafe.drivers.unittest.decorators import tags
from cloudcafe.common.tools.datagen import rand_name
from cloudcafe.compute.common.types import NovaServerRebootTypes
from cloudroast.compute.fixtures import ServerFromImageFixture


class RebootServerHardTests(object):

    @tags(type='smoke', net='yes')
    def test_reboot_server_hard(self):
        """
        A server should be able to successfully be hard rebooted

        Get a remote instance client for the server identified during test set
        up. Get the uptime value for the OS on the server. Request a hard
        reboot of the server. Time the reboot. Once the reboot completes get a
        new remote instance client for the server and use it to get the uptime
        of the server after the hard reboot. Validate that the uptime of the
        server post soft reboot is less than the uptime prior to the reboot
        plus the time it took for the reboot to complete.

        The following assertions will occur:
            - The value of uptime after the hard reboot will be less that the
              uptime of the uptime from before the reboot plus the amount of
              time it takes for the reboot to occur.
        """
        remote_instance = self.server_behaviors.get_remote_instance_client(
            self.server, config=self.servers_config, key=self.key.private_key)
        uptime_start = remote_instance.get_uptime()
        start = time.time()

        self.server_behaviors.reboot_and_await(
            self.server.id, NovaServerRebootTypes.HARD)
        remote_client = self.server_behaviors.get_remote_instance_client(
            self.server, config=self.servers_config, key=self.key.private_key)
        finish = time.time()
        uptime_post_reboot = remote_client.get_uptime()
        self.assertLess(uptime_post_reboot, (uptime_start + (finish - start)))


class ServerFromImageRebootServerHardTests(ServerFromImageFixture,
                                           RebootServerHardTests):

    @classmethod
    def setUpClass(cls):
        """
        Perform actions that setup the necessary resources for testing

        The following resources are created during this setup:
            - A keypair with a random name starting with 'key'
            - A server using the created keypair and values from the test
              configuration
        """
        super(ServerFromImageRebootServerHardTests, cls).setUpClass()
        cls.key = cls.keypairs_client.create_keypair(rand_name("key")).entity
        cls.resources.add(cls.key.name,
                          cls.keypairs_client.delete_keypair)
        cls.create_server(key_name=cls.key.name)
