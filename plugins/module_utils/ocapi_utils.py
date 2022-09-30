# -*- coding: utf-8 -*-
# Copyright (c) 2022 Western Digital Corporation
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import os
import uuid

from ansible.module_utils.urls import open_url
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError


GET_HEADERS = {'accept': 'application/json'}
PUT_HEADERS = {'content-type': 'application/json', 'accept': 'application/json'}
POST_HEADERS = {'content-type': 'application/json', 'accept': 'application/json'}

HEALTH_OK = 5


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
            return {'ret': False,
                    'msg': "HTTP Error %s on GET request to '%s'"
                           % (e.code, uri),
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
            return {'ret': False,
                    'msg': "HTTP Error %s on PUT request to '%s'"
                           % (e.code, uri),
                    'status': e.code}
        except URLError as e:
            return {'ret': False, 'msg': "URL Error on PUT request to '%s': '%s'"
                                         % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed PUT request to '%s': '%s'" % (uri, to_text(e))}
        return {'ret': True, 'headers': headers, 'resp': resp}

    def post_request(self, uri, payload, content_type="application/json", timeout=None):
        req_headers = dict(POST_HEADERS)
        if content_type != "application/json":
            req_headers["content-type"] = content_type
        username, password, basic_auth = self._auth_params()
        if content_type == "application/json":
            request_data = json.dumps(payload)
        else:
            request_data = payload
        try:
            resp = open_url(uri, data=request_data,
                            headers=req_headers, method="POST",
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout if timeout is None else timeout)
            headers = dict((k.lower(), v) for (k, v) in resp.info().items())
        except HTTPError as e:
            return {'ret': False,
                    'msg': "HTTP Error %s on POST request to '%s'"
                           % (e.code, uri),
                    'status': e.code}
        except URLError as e:
            return {'ret': False, 'msg': "URL Error on POST request to '%s': '%s'"
                                         % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed POST request to '%s': '%s'" % (uri, to_text(e))}
        return {'ret': True, 'headers': headers, 'resp': resp}

    def manage_system_power(self, command):
        if command == "PowerGracefulRestart":
            resource_uri = self.root_uri

            # Get the resource so that we have the Etag
            response = self.get_request(resource_uri)
            if 'etag' not in response['headers']:
                return {'ret': False, 'msg': 'Etag not found in response.'}
            etag = response['headers']['etag']
            if response['ret'] is False:
                return response

            # Issue the PUT to do the reboot (unless we are in check mode)
            if self.module.check_mode:
                return {
                    'ret': True,
                    'changed': True,
                    'msg': 'Update not performed in check mode.'
                }
            payload = {'Reboot': True}
            response = self.put_request(resource_uri, payload, etag)
            if response['ret'] is False:
                return response
        else:
            return {'ret': False, 'msg': 'Invalid command.'}

        return {'ret': True}

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

            # Set the LED (unless we are in check mode)
            if self.module.check_mode:
                return {
                    'ret': True,
                    'changed': True,
                    'msg': 'Update not performed in check mode.'
                }
            payload = {'IndicatorLED': payloads[command]}
            response = self.put_request(resource_uri, payload, etag)
            if response['ret'] is False:
                return response
        else:
            return {'ret': False, 'msg': 'Invalid command'}

        return {'ret': True}

    def prepare_multipart_firmware_upload(self, filename):
        """Prepare a multipart/form-data body for OCAPI firmware upload.

        :arg filename: The name of the file to upload.
        :returns: tuple of (content_type, body) where ``content_type`` is
            the ``multipart/form-data`` ``Content-Type`` header including
            ``boundary`` and ``body`` is the prepared bytestring body

        Prepares the body to include "FirmwareFile" field with the contents of the file.
        Because some OCAPI targets do not support Base-64 encoding for multipart/form-data,
        this method sends the file as binary.
        """
        boundary = str(uuid.uuid4())  # Generate a random boundary
        body = "--" + boundary + '\r\n'
        body += 'Content-Disposition: form-data; name="FirmwareFile"; filename="%s"\r\n' % to_native(os.path.basename(filename))
        body += 'Content-Type: application/octet-stream\r\n\r\n'
        body_bytes = bytearray(body, 'utf-8')
        with open(filename, 'rb') as f:
            body_bytes += f.read()
        body_bytes += bytearray("\r\n--%s--" % boundary, 'utf-8')
        return ("multipart/form-data; boundary=%s" % boundary,
                body_bytes)

    def upload_firmware_image(self, update_image_path):
        if not (os.path.exists(update_image_path) and os.path.isfile(update_image_path)):
            return {'ret': False, 'msg': 'File does not exist.'}
        url = self.root_uri + "OperatingSystem"
        content_type, b_form_data = self.prepare_multipart_firmware_upload(update_image_path)

        # Post the firmware (unless we are in check mode)
        if self.module.check_mode:
            return {
                'ret': True,
                'changed': True,
                'msg': 'Update not performed in check mode.'
            }
        result = self.post_request(url, b_form_data, content_type=content_type, timeout=300)
        if result['ret'] is False:
            return result
        return {'ret': True}

    def update_firmware_image(self):
        resource_uri = self.root_uri
        # We have to do a GET to obtain the Etag.  It's required on the PUT.
        response = self.get_request(resource_uri)
        if response['ret'] is False:
            return response
        if 'etag' not in response['headers']:
            return {'ret': False, 'msg': 'Etag not found in response.'}
        etag = response['headers']['etag']

        # Issue the PUT (unless we are in check mode)
        if self.module.check_mode:
            return {
                'ret': True,
                'changed': True,
                'msg': 'Update not performed in check mode.'
            }
        payload = {'FirmwareUpdate': True}
        response = self.put_request(resource_uri, payload, etag)
        if response['ret'] is False:
            return response

        return {'ret': True, 'statusMonitor': response["headers"]["location"]}

    def activate_firmware_image(self):
        resource_uri = self.root_uri
        # We have to do a GET to obtain the Etag.  It's required on the PUT.
        response = self.get_request(resource_uri)
        if 'etag' not in response['headers']:
            return {'ret': False, 'msg': 'Etag not found in response.'}
        etag = response['headers']['etag']
        if response['ret'] is False:
            return response

        # Issue the PUT (unless we are in check mode)
        if self.module.check_mode:
            return {
                'ret': True,
                'changed': True,
                'msg': 'Update not performed in check mode.'
            }
        payload = {'FirmwareActivate': True}
        response = self.put_request(resource_uri, payload, etag)
        if response['ret'] is False:
            return response

        return {'ret': True, 'statusMonitor': response["headers"]["location"]}

    def get_job_status(self, status_monitor):
        response = self.get_request(status_monitor)
        if response['ret'] is False:
            return response
        details = response["data"]["Status"].get("Details")
        if type(details) is str:
            details = [details]
        health_list = response["data"]["Status"]["Health"]
        return_value = {
            "ret": True,
            "percentComplete": response["data"]["PercentComplete"],
            "operationStatus": response["data"]["Status"]["State"]["Name"],
            "operationStatusId": response["data"]["Status"]["State"]["ID"],
            "operationHealth": health_list[0]["Name"] if len(health_list) > 0 else None,
            "operationHealthId": health_list[0]["ID"] if len(health_list) > 0 else None,
            "details": details
        }
        return return_value

    def get_system_status(self):
        response = self.get_request(self.root_uri)
        if response['ret'] is False:
            return response
        return_value = {
            "ret": True,
            "status": response["data"]["Status"]
        }
        return return_value


