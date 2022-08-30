# -*- coding: utf-8 -*-
# Copyright (c) 2022 Western Digital Corporation
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
from ansible.module_utils.urls import open_url
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError


GET_HEADERS = {'accept': 'application/json'}
PUT_HEADERS = {'content-type': 'application/json', 'accept': 'application/json'}


class OcapiUtils(object):

    def __init__(self, creds, root_uris, timeout, module):
        self.root_uri = root_uris[0]
        self.creds = creds
        self.timeout = timeout
        self.module = module
        # Update the root URI if the first one is not a valid OCAPI URI.
        self._set_root_uri(root_uris)

    def _set_root_uri(self, root_uris):
        """Set the root URI from a list of options.

        If the current root URI is good, just keep it.  Else cycle through our options until we find a good one.
        A URI is considered good if a GET response is successful, returns JSON, and has a "Self" property.
        """
        for root_uri in root_uris:
            response = self.get_request(root_uri)
            if response['ret']:
                data = response['data']
                if "Self" in data:
                    self.root_uri = root_uri
                    break

    def _auth_params(self):
        """
        Return tuple of required authentication params based on the username and password.

        :return: tuple of username, password
        """
        username = self.creds['user']
        password = self.creds['pswd']
        force_basic_auth = True
        return username, password, force_basic_auth

    def get_request(self, uri):
        req_headers = dict(GET_HEADERS)
        username, password, basic_auth = self._auth_params()
        try:
            resp = open_url(uri, method="GET", headers=req_headers,
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
            data = json.loads(to_native(resp.read()))
            headers = dict((k.lower(), v) for (k, v) in resp.info().items())
        except HTTPError as e:
            msg = self._get_extended_message(e)
            return {'ret': False,
                    'msg': "HTTP Error %s on GET request to '%s', extended message: '%s'"
                           % (e.code, uri, msg),
                    'status': e.code}
        except URLError as e:
            return {'ret': False, 'msg': "URL Error on GET request to '%s': '%s'"
                                         % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed GET request to '%s': '%s'" % (uri, to_text(e))}
        return {'ret': True, 'data': data, 'headers': headers}

    def put_request(self, uri, payload, etag=None):
        req_headers = dict(PUT_HEADERS)
        if etag is not None:
            req_headers['If-Match'] = etag
        username, password, basic_auth = self._auth_params()
        try:
            resp = open_url(uri, data=json.dumps(payload),
                            headers=req_headers, method="PUT",
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
            headers = dict((k.lower(), v) for (k, v) in resp.info().items())
        except HTTPError as e:
            msg = self._get_extended_message(e)
            return {'ret': False,
                    'msg': "HTTP Error %s on PUT request to '%s', extended message: '%s'"
                           % (e.code, uri, msg),
                    'status': e.code}
        except URLError as e:
            return {'ret': False, 'msg': "URL Error on PUT request to '%s': '%s'"
                                         % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed PUT request to '%s': '%s'" % (uri, to_text(e))}
        return {'ret': True, 'headers': headers, 'resp': resp}

    def manage_chassis_indicator_led(self, command):
        """Process a command to manage the chassis indicator LED.

        :param string command: The Ansible command being processed.
        """
        return self.manage_indicator_led(command, self.root_uri)

    def manage_indicator_led(self, command, resource_uri=None):
        """Process a command to manage an indicator LED.

        :param string command: The Ansible command being processed.
        :param string resource_uri: URI of the resource whose indicator LED is being managed.
        """
        key = "IndicatorLED"
        if resource_uri is None:
            resource_uri = self.root_uri

        payloads = {
            'IndicatorLedOn': {
                'ID': 2
            },
            'IndicatorLedOff': {
                'ID': 4
            }
        }

        response = self.get_request(resource_uri)
        if 'etag' not in response['headers']:
            return {'ret': False, 'msg': 'Etag not found in response.'}
        etag = response['headers']['etag']
        if response['ret'] is False:
            return response
        data = response['data']
        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}
        if 'ID' not in data[key]:
            return {'ret': False, 'msg': 'IndicatorLED for resource has no ID.'}

        if command in payloads.keys():
            # See if the LED is already set as requested.
            current_led_status = data[key]['ID']
            if current_led_status == payloads[command]['ID']:
                return {'ret': True, 'changed': False}

            # Set the LED.
            payload = {'IndicatorLED': payloads[command]}
            response = self.put_request(resource_uri, payload, etag)
            if response['ret'] is False:
                return response
        else:
            return {'ret': False, 'msg': 'Invalid command'}

        return {'ret': True}
