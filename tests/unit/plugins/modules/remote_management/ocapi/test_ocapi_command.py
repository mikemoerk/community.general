# -*- coding: utf-8 -*-
# Copyright (c) Ansible project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import shutil
import tempfile

from ansible_collections.community.general.tests.unit.compat.mock import patch
from ansible_collections.community.general.tests.unit.compat import unittest
from ansible.module_utils import basic
import ansible_collections.community.general.plugins.modules.remote_management.ocapi.ocapi_command as module
from ansible_collections.community.general.tests.unit.plugins.modules.utils import AnsibleExitJson, AnsibleFailJson
from ansible_collections.community.general.tests.unit.plugins.modules.utils import set_module_args, exit_json, fail_json

MOCK_BASE_URI = "mockBaseUri/"
OPERATING_SYSTEM_URI = "OperatingSystem"

ACTION_WAS_SUCCESSFUL = "Action was successful."
UPDATE_NOT_PERFORMED_IN_CHECK_MODE = "Update not performed in check mode."
NO_ACTION_PERFORMED_IN_CHECK_MODE = "No action performed in check mode."

MOCK_SUCCESSFUL_HTTP_RESPONSE_LED_INDICATOR_OFF = {
    "ret": True,
    "data": {
        "IndicatorLED": {
            "ID": 4,
            "Name": "Off"
        }
    },
    "headers": {"etag": "MockETag"}
}

MOCK_SUCCESSFUL_HTTP_PUT_RESPONSE_WITH_ETAG = {
    "ret": True,
    "data": {}
}

MOCK_SUCCESSFUL_HTTP_POST_RESPONSE = {
    "ret": True,
    "data": {}
}


def get_bin_path(self, arg, required=False):
    """Mock AnsibleModule.get_bin_path"""
    return arg


def get_exception_message(ansible_exit_json):
    """From an AnsibleExitJson exception, get the message string."""
    return ansible_exit_json.exception.args[0]["msg"]


def is_changed(ansible_exit_json):
    """From an AnsibleExitJson exception, return the value of the changed flag"""
    return ansible_exit_json.exception.args[0]["changed"]


def mock_get_request(*args, **kwargs):
    """Mock for get_request."""
    url = args[1]
    if url == 'https://' + MOCK_BASE_URI:
        return MOCK_SUCCESSFUL_HTTP_RESPONSE_LED_INDICATOR_OFF
    raise RuntimeError("Illegal call to get_request in test: " + args[1])


def mock_put_request(*args, **kwargs):
    """Mock put_request."""
    url = args[1]
    if url == 'https://' + MOCK_BASE_URI:
        return MOCK_SUCCESSFUL_HTTP_RESPONSE_LED_INDICATOR_OFF
    raise RuntimeError("Illegal PUT call to: " + args[1])


def mock_post_request(*args, **kwargs):
    """Mock post_request."""
    url = args[1]
    if url == 'https://' + MOCK_BASE_URI + OPERATING_SYSTEM_URI:
        return MOCK_SUCCESSFUL_HTTP_POST_RESPONSE
    raise RuntimeError("Illegal POST call to: " + args[1])


def mock_invalid_http_request(*args, **kwargs):
    """Mock to make an HTTP request invalid.  Raises an exception."""
    raise RuntimeError("Illegal HTTP call to " + args[1])


class TestOcapiCommand(unittest.TestCase):

    def setUp(self):
        self.mock_module_helper = patch.multiple(basic.AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json,
                                                 get_bin_path=get_bin_path)
        self.mock_module_helper.start()
        self.addCleanup(self.mock_module_helper.stop)
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_module_fail_when_required_args_missing(self):
        with self.assertRaises(AnsibleFailJson) as ansible_fail_json:
            set_module_args({})
            module.main()
        self.assertIn("missing required arguments:", get_exception_message(ansible_fail_json))

    def test_module_fail_when_unknown_category(self):
        with self.assertRaises(AnsibleFailJson) as ansible_fail_json:
            set_module_args({
                'category': 'unknown',
                'command': 'IndicatorLedOn',
                'username': 'USERID',
                'password': 'PASSW0RD=21',
                'ioms': ["iom1"],
            })
            module.main()
        self.assertIn("Invalid Category 'unknown", get_exception_message(ansible_fail_json))

    def test_module_fail_when_ioms_list_empty(self):
        with self.assertRaises(AnsibleFailJson) as ansible_fail_json:
            set_module_args({
                'category': 'unknown',
                'command': 'IndicatorLedOn',
                'username': 'USERID',
                'password': 'PASSW0RD=21',
                'ioms': [],
            })
            module.main()
        self.assertEqual("Must specify base uri or non-empty ioms list.", get_exception_message(ansible_fail_json))

    def test_set_chassis_led_indicator(self):
        """Test that we can set chassis LED indicator"""
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Chassis',
                    'command': 'IndicatorLedOn',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21'
                })
                module.main()
            self.assertEqual(ACTION_WAS_SUCCESSFUL, get_exception_message(ansible_exit_json))
            self.assertTrue(is_changed(ansible_exit_json))

    def test_set_chassis_led_indicator_check_mode(self):
        """Test check mode when setting chassis LED indicator"""
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_invalid_http_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Chassis',
                    'command': 'IndicatorLedOn',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21',
                    '_ansible_check_mode': True
                })
                module.main()
            self.assertEqual(UPDATE_NOT_PERFORMED_IN_CHECK_MODE, get_exception_message(ansible_exit_json))
            self.assertTrue(is_changed(ansible_exit_json))

    def test_set_chassis_led_indicator_already_set(self):
        """Test that if we set LED Indicator to off when it's already off, we get changed=False."""
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Chassis',
                    'command': 'IndicatorLedOff',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21'
                })
                module.main()
            self.assertEqual(ACTION_WAS_SUCCESSFUL, get_exception_message(ansible_exit_json))
            self.assertFalse(is_changed(ansible_exit_json))

    def test_set_chassis_led_indicator_already_set_check_mode(self):
        """Test that if we set LED Indicator to off when it's already off, we get changed=False even in check mode."""
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_invalid_http_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Chassis',
                    'command': 'IndicatorLedOff',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21',
                    "_ansible_check_mode": True
                })
                module.main()
            self.assertEqual(NO_ACTION_PERFORMED_IN_CHECK_MODE, get_exception_message(ansible_exit_json))
            self.assertFalse(is_changed(ansible_exit_json))

    def test_set_chassis_invalid_indicator_command(self):
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request):
            with self.assertRaises(AnsibleFailJson) as ansible_fail_json:
                set_module_args({
                    'category': 'Chassis',
                    'command': 'IndicatorLedBright',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21'
                })
                module.main()
            self.assertIn("Invalid Command", get_exception_message(ansible_fail_json))

    def test_reset_enclosure(self):
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Systems',
                    'command': 'PowerGracefulRestart',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21'
                })
                module.main()
            self.assertEqual(ACTION_WAS_SUCCESSFUL, get_exception_message(ansible_exit_json))
            self.assertTrue(is_changed(ansible_exit_json))

    def test_reset_enclosure_check_mode(self):
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_invalid_http_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Systems',
                    'command': 'PowerGracefulRestart',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21',
                    "_ansible_check_mode": True
                })
                module.main()
            self.assertEqual(UPDATE_NOT_PERFORMED_IN_CHECK_MODE, get_exception_message(ansible_exit_json))
            self.assertTrue(is_changed(ansible_exit_json))

    def test_firmware_upload_missing_update_image_path(self):
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request):
            with self.assertRaises(AnsibleFailJson) as ansible_fail_json:
                set_module_args({
                    'category': 'Update',
                    'command': 'FWUpload',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21'
                })
                module.main()
            self.assertEqual("Missing update_image_path.", get_exception_message(ansible_fail_json))

    def test_firmware_upload_file_not_found(self):
        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request):
            with self.assertRaises(AnsibleFailJson) as ansible_fail_json:
                set_module_args({
                    'category': 'Update',
                    'command': 'FWUpload',
                    'update_image_path': 'nonexistentfile.bin',
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21'
                })
                module.main()
            self.assertEqual("File does not exist.", get_exception_message(ansible_fail_json))

    def test_firmware_upload(self):
        filename = "fake_firmware.bin"
        filepath = os.path.join(self.tempdir, filename)
        file_contents = b'\x00\x01\x02\x03\x04'
        with open(filepath, 'wb+') as f:
            f.write(file_contents)

        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request,
                            post_request=mock_post_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Update',
                    'command': 'FWUpload',
                    'update_image_path': filepath,
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21'
                })
                module.main()
            self.assertEqual(ACTION_WAS_SUCCESSFUL, get_exception_message(ansible_exit_json))
            self.assertTrue(is_changed(ansible_exit_json))

    def test_firmware_upload_check_mode(self):
        filename = "fake_firmware.bin"
        filepath = os.path.join(self.tempdir, filename)
        file_contents = b'\x00\x01\x02\x03\x04'
        with open(filepath, 'wb+') as f:
            f.write(file_contents)

        with patch.multiple("ansible_collections.community.general.plugins.module_utils.ocapi_utils.OcapiUtils",
                            get_request=mock_get_request,
                            put_request=mock_put_request,
                            post_request=mock_invalid_http_request):
            with self.assertRaises(AnsibleExitJson) as ansible_exit_json:
                set_module_args({
                    'category': 'Update',
                    'command': 'FWUpload',
                    'update_image_path': filepath,
                    'baseuri': MOCK_BASE_URI,
                    'username': 'USERID',
                    'password': 'PASSWORD=21',
                    "_ansible_check_mode": True
                })
                module.main()
            self.assertEqual(UPDATE_NOT_PERFORMED_IN_CHECK_MODE, get_exception_message(ansible_exit_json))
            self.assertTrue(is_changed(ansible_exit_json))
