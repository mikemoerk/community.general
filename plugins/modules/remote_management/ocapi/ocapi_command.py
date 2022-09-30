#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Western Digital Corporation
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ocapi_command
short_description: Manages Out-Of-Band controllers using Open Composable API (OCAPI).
description:
  - Builds OCAPI URIs locally and sends them to remote OOB controllers to
    perform an action.
  - Manages OOB controller such as Indicator LED, Reboot, Power Mode, Firmware Update.
options:
  category:
    required: true
    description:
      - Category to execute on OOB controller.
    type: str
  command:
    required: true
    description:
      - Command to execute on OOB controller.
    type: str
  baseuri:
    description:
      - Base URI of OOB controller.  Must include this or I(ioms).
    type: str
  ioms:
    description:
      - List of IOM FQDNs for the enclosure.  Must include this or I(baseuri).
    type: list
    elements: str
  update_image_path:
    required: false
    description:
      - For FWUpload, the path on the local filesystem of the firmware update image.
    type: str
  username:
    required: true
    description:
      - Username for authenticating to OOB controller.
    type: str
  password:
    required: true
    description:
      - Password for authenticating to OOB controller.
    type: str
  timeout:
    description:
      - Timeout in seconds for URL requests to OOB controller.
    default: 10
    type: int

author: "Mike Moerk (@mikemoerk)"
'''

EXAMPLES = '''
  - name: Set chassis indicator LED to on
    community.general.ocapi_command:
      category: Chassis
      command: IndicatorLedOn
      ioms: "{{ ioms }}"
      username: "{{ username }}"
      password: "{{ password }}"
  - name: Set chassis indicator LED to off
    community.general.ocapi_command:
      category: Chassis
      command: IndicatorLedOff
      ioms: "{{ ioms }}"
      username: "{{ username }}"
      password: "{{ password }}"
  - name: Reset Enclosure
    community.general.ocapi_command:
      category: Systems
      command: PowerGracefulRestart
      ioms: "{{ ioms }}"
      username: "{{ username }}"
      password: "{{ password }}"
  - name: Firmware Upload
    community.general.ocapi_command:
      category: Update
      command: FWUpload
      baseuri: "iom1.wdc.com"
      username: "{{ username }}"
      password: "{{ password }}"
      update_image_path: "/path/to/firmware.tar.gz"
  - name: Firmware Update
    community.general.ocapi_command:
      category: Update
      command: FWUpdate
      baseuri: "iom1.wdc.com"
      username: "{{ username }}"
      password: "{{ password }}"
  - name: Firmware Activate
    community.general.ocapi_command:
      category: Update
      command: FWActivate
      baseuri: "iom1.wdc.com"
      username: "{{ username }}"
      password: "{{ password }}"
'''

RETURN = '''
msg:
    description: Message with action result or error description
    returned: always
    type: str
    sample: "Action was successful"
    
statusMonitor:
    description: Token to use to monitor status of the operation.  Returned for async commands such as Firmware Update, Firmware Activate.
    returned: when supported
    type: str
    sample: "https://ioma.wdc.com/Storage/Devices/openflex-data24-usalp03020qb0003/Jobs/FirmwareUpdate/"

operationStatusId:
    description: OCAPI State ID (see OCAPI documentation for possible values)
    returned: when supported
    type: int
    sample: 2

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.general.plugins.module_utils.ocapi_utils import OcapiUtils
from ansible.module_utils.common.text.converters import to_native


# More will be added as module features are expanded
CATEGORY_COMMANDS_ALL = {
    "Chassis": ["IndicatorLedOn", "IndicatorLedOff"],
    "Systems": ["PowerGracefulRestart"],
    "Update": ["FWUpload", "FWUpdate", "FWActivate"]
}


def main():
    result = {}
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(required=True),
            command=dict(required=True, type='str'),
            ioms=dict(type='list', elements='str'),
            baseuri=dict(),
            update_image_path=dict(type='str'),
            username=dict(required=True),
            password=dict(required=True, no_log=True),
            timeout=dict(type='int', default=10)
        ),
        required_one_of=[
            ('ioms', 'baseuri')
        ],
        supports_check_mode=True
    )

    category = module.params['category']
    command = module.params['command']

    # admin credentials used for authentication
    creds = {
        'user': module.params['username'],
        'pswd': module.params['password']
    }

    # timeout
    timeout = module.params['timeout']

    # Build root URI(s)
    if module.params.get("baseuri") is not None:
        root_uris = ["https://" + module.params['baseuri']]
    else:
        root_uris = [
            "https://" + iom for iom in module.params['ioms']
        ]
    if len(root_uris) == 0:
        module.fail_json(msg=to_native("Must specify base uri or non-empty ioms list."))
    ocapi_utils = OcapiUtils(creds, root_uris, timeout, module)

    # Check that Category is valid
    if category not in CATEGORY_COMMANDS_ALL:
        module.fail_json(msg=to_native("Invalid Category '%s'. Valid Categories = %s" % (category, list(CATEGORY_COMMANDS_ALL.keys()))))

    # Check that the command is valid
    if command not in CATEGORY_COMMANDS_ALL[category]:
        module.fail_json(msg=to_native("Invalid Command '%s'. Valid Commands = %s" % (command, CATEGORY_COMMANDS_ALL[category])))

    # Organize by Categories / Commands
    if category == "Chassis":
        if command.startswith("IndicatorLed"):
            result = ocapi_utils.manage_chassis_indicator_led(command)
    elif category == "Systems":
        if command.startswith("Power"):
            result = ocapi_utils.manage_system_power(command)
    elif category == "Update":
        if module.params.get("ioms") is not None:
            module.fail_json(msg="Cannot specify ioms list for firmware operations.  Specify baseuri instead.")
        if command == "FWUpload":
            update_image_path = module.params.get("update_image_path")
            if update_image_path is None:
                module.fail_json(msg=to_native("Missing update_image_path."))
            result = ocapi_utils.upload_firmware_image(update_image_path)
        elif command == "FWUpdate":
            result = ocapi_utils.update_firmware_image()
        elif command == "FWActivate":
            result = ocapi_utils.activate_firmware_image()

    if result['ret'] is False:
        module.fail_json(msg=to_native(result['msg']))
    else:
        del result['ret']
        changed = result.get('changed', True)
        session = result.get('session', dict())
        kwargs = {
            "changed": changed,
            "session": session,
            "msg": "Action was successful." if not module.check_mode else result.get(
                "msg", "No action performed in check mode."
            )
        }
        result_keys = [result_key for result_key in result if result_key not in kwargs]
        for result_key in result_keys:
            kwargs[result_key] = result[result_key]
        module.exit_json(**kwargs)


if __name__ == '__main__':
    main()
