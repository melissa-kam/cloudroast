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
import json
import math
import md5
from random import choice

from cafe.common.unicode import UNICODE_BLOCKS, BLOCK_NAMES
from cafe.drivers.unittest.datasets import DatasetList
from cloudroast.objectstorage.fixtures import ObjectStorageAuthComposite
from cloudcafe.objectstorage.objectstorage_api.behaviors \
    import ObjectStorageAPI_Behaviors
from cloudcafe.objectstorage.objectstorage_api.client \
    import ObjectStorageAPIClient
from cloudcafe.objectstorage.objectstorage_api.config \
    import ObjectStorageAPIConfig


CONTENT_TYPES = {
    'text': 'text/plain; charset=UTF-8'
}


class ObjectDatasetList(DatasetList):
    """
    Handles creation of differing types of objects for use with data driven
    tests.
    """

    def __init__(self, exclude=None):
        api_config = ObjectStorageAPIConfig()
        auth_data = ObjectStorageAuthComposite()
        client = ObjectStorageAPIClient(
            auth_data.storage_url, auth_data.auth_token)
        behaviors = ObjectStorageAPI_Behaviors(client, api_config)
        features = behaviors.get_configured_features()

        if features == api_config.ALL_FEATURES:
            features = ['dlo', 'slo']

        generator = ObjectStorageGenerator(client)

        if exclude is None:
            exclude = []

        if 'standard' not in exclude:
            self.append_new_dataset(
                'standard',
                {'generate_object': generator.generate_object})

        if 'dlo' in features and 'dlo' not in exclude:
            self.append_new_dataset(
                'dlo',
                {'generate_object': generator.generate_dynamic_large_object})

        if 'slo' in features and 'slo' not in exclude:
            self.append_new_dataset(
                'slo',
                {'generate_object': generator.generate_static_large_object})


class ObjectStorageGenerator(object):
    """
    Generates objects for testing.
    """

    def __init__(self, client):
        self.client = client
        self.api_config = ObjectStorageAPIConfig()

    def generate_object(self, container_name, object_name,
                        data_size=None, data_pool=None, data_op=None,
                        headers=None, params=None):
        """
        Create a standard object (non slo/dlo)

        @param container_name: container to create the object in
        @type container_name: string
        @param object_name: name of object to be created
        @type object_name: string
        @param data_size: size of object to be created
        @type data_size: int
        @param data_pool: characters to use in generating object content
        @type data_size: list of characters
        @param data_op: function to execute on the data generated.
                        The function signature should be as follows:
                            def data_op(data, extra_data)
                        Where:
                            data - the data generated for the object
                            extra_data - info about the object
                         The function should return a tuple representing
                         these same fields.
        @type data_op: function reference
        @param headers: headers to be used when creating the object
        @type headers: dict
        @param params: query string parameters to be used when creating the
                       object
        @type params: dict

        @return: data about the generated object
        @type: dict
        """
        if not data_size:
            data_size = 100

        if not data_pool:
            data_pool = [x for x in UNICODE_BLOCKS.get_range(
                BLOCK_NAMES.basic_latin).encoded_codepoints()]

        object_data = ''.join([choice(data_pool) for x in xrange(data_size)])
        extra_data = {}
        if data_op is not None:
            (object_data, extra_data) = data_op(object_data, extra_data)
        data_md5 = md5.new(object_data).hexdigest()
        data_etag = data_md5

        default_headers = {'Content-Length': str(len(object_data)),
                           'Content-Type': CONTENT_TYPES.get('text'),
                           'Etag': data_etag}

        if headers is None:
            headers = {}

        all_headers = dict(default_headers)
        for key, value in headers.iteritems():
            all_headers[key] = value

        response = self.client.create_object(
            container_name, object_name, data=object_data,
            headers=all_headers)

        return {'md5': data_md5,
                'etag': data_etag,
                'size': data_size,
                'type': 'standard',
                'response': response,
                'extra': extra_data}

    def generate_dynamic_large_object(self, container_name, object_name,
                                      segment_size=None, data_size=None,
                                      data_pool=None, data_op=None,
                                      headers=None, params=None):
        """
        Create a dynamic large object from provided data.

        @param container_name: container to create the object in
        @type container_name: string
        @param object_name: name of object to be created
        @type object_name: string
        @param data_size: size of object to be created
        @type data_size: int
        @param data_pool: characters to use in generating object content
        @type data_size: list of characters
        @param data_op: function to execute on the data generated.
                        The function signature should be as follows:
                            def data_op(data, extra_data)
                        Where:
                            data - the data generated for the object
                            extra_data - info about the object
                         The function should return a tuple representing
                         these same fields.
        @type data_op: function reference
        @param headers: headers to be used when creating the object
        @type headers: dict
        @param params: query string parameters to be used when creating the
                       object
        @type params: dict

        @return: data about the generated segments and  object
        @type: dict
        """
        if not data_size:
            data_size = 550

        if not data_pool:
            data_pool = [x for x in UNICODE_BLOCKS.get_range(
                BLOCK_NAMES.basic_latin).encoded_codepoints()]

        if not segment_size:
            segment_size = 100

        num_segments = int(math.ceil(data_size / float(segment_size)))

        data_md5 = md5.new()
        data_etag = md5.new()

        extra_data = {'segments': []}
        for segment_id in [x for x in xrange(num_segments)]:
            if segment_id + 1 == num_segments:
                segment_size = data_size % segment_size
            segment_name = 'segment.{0}.{1}'.format(object_name, segment_id)
            segment_data = ''.join([choice(data_pool) for x in xrange(
                segment_size)])
            segment_md5 = md5.new(segment_data).hexdigest()
            segment_extra_data = {'name': segment_name,
                                  'size': segment_size,
                                  'md5': segment_md5}
            if data_op is not None:
                (segment_data, segment_extra_data) = data_op(
                    segment_data, segment_extra_data)
            extra_data['segments'].append(segment_extra_data)
            segment_etag = md5.new(segment_data)
            segment_etag = segment_etag.hexdigest()
            data_md5.update(segment_data)
            data_etag.update(segment_etag)
            self.client.create_object(
                container_name, segment_name, data=segment_data)

        default_headers = {'X-Object-Manifest': '{0}/segment.{1}'.format(
            container_name, object_name)}

        if headers is None:
            headers = {}

        all_headers = dict(default_headers)
        for key, value in headers.iteritems():
            all_headers[key] = value

        response = self.client.create_object(
            container_name, object_name, headers=all_headers)

        return {'md5': data_md5.hexdigest(),
                'etag': data_etag.hexdigest(),
                'size': data_size,
                'type': 'dlo',
                'response': response,
                'extra': extra_data}

    def generate_static_large_object(self, container_name, object_name,
                                     data_size=None, data_pool=None,
                                     data_op=None, segment_size=None,
                                     headers=None, params=None):
        """
        Generate a static large object from provided data.

        @param container_name: container to create the object in
        @type container_name: string
        @param object_name: name of object to be created
        @type object_name: string
        @param data_size: size of object to be created
        @type data_size: int
        @param data_pool: characters to use in generating object content
        @type data_size: list of characters
        @param data_op: function to execute on the data generated.
                        The function signature should be as follows:
                            def data_op(data, extra_data)
                        Where:
                            data - the data generated for the object
                            extra_data - info about the object
                         The function should return a tuple representing
                         these same fields.
        @type data_op: function reference
        @param headers: headers to be used when creating the object
        @type headers: dict
        @param params: query string parameters to be used when creating the
                       object
        @type params: dict

        @return: data about the generated segments and  object
        @type: dict
        """
        if not data_size:
            data_size = int(self.api_config.min_slo_segment_size * 3.5)

        if not data_pool:
            data_pool = [x for x in UNICODE_BLOCKS.get_range(
                BLOCK_NAMES.basic_latin).encoded_codepoints()]

        if not segment_size:
            segment_size = self.api_config.min_slo_segment_size

        num_segments = int(math.ceil(data_size / float(segment_size)))

        manifest = []

        data_md5 = md5.new()
        data_etag = md5.new()

        extra_data = {'segments': []}
        for segment_id in [x for x in xrange(num_segments)]:
            if segment_id + 1 == num_segments:
                segment_size = data_size % segment_size

            segment_name = '{0}.{1}'.format(object_name, segment_id)
            segment_path = '/{0}/{1}'.format(container_name, segment_name)
            segment_data = ''.join([choice(data_pool) for x in xrange(
                segment_size)])
            segment_md5 = md5.new(segment_data).hexdigest()
            segment_extra_data = {'name': segment_name,
                                  'size': segment_size,
                                  'md5': segment_md5}
            if data_op is not None:
                (segment_data, segment_extra_data) = data_op(
                    segment_data, segment_extra_data)
            extra_data['segments'].append(segment_extra_data)
            segment_etag = md5.new(segment_data)
            segment_etag = segment_etag.hexdigest()
            data_md5.update(segment_data)
            data_etag.update(segment_etag)

            self.client.create_object(
                container_name, segment_name, data=segment_data)

            manifest.append({'path': segment_path, 'etag': segment_etag,
                             'size_bytes': segment_size})

        response = self.client.create_object(
            container_name, object_name, data=json.dumps(manifest),
            params={'multipart-manifest': 'put'}, headers=headers)

        return {'md5': data_md5.hexdigest(),
                'etag': data_etag.hexdigest(),
                'size': data_size,
                'response': response,
                'extra': extra_data}