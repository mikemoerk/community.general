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
  - Manages OOB controller such as Indicator LED, reboot, power mode, firmware update.
options:
  category:
    required: true
    description:
      - Category to execute on OOB controller.
    type: str
  command:
    required: true
    description:
      - List of commands to execute on OOB controller.
    type: list
    elements: str
  baseuri:
    description:
      - Base URI of OOB controller.  Must include this or I(ioms).
    type: str
  ioms:
    description:
      - List of IOM FQDNs for the enclosure.  Must include this or I(baseuri).
    type: list
    elements: str
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
  - name: Set system indicator LED to on
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

'''

RETURN = '''
msg:
    description: Message with action result or error description
    returned: always
    type: str
    sample: "Action was successful"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.general.plugins.module_utils.ocapi_utils import OcapiUtils
from ansible.module_utils.common.text.converters import to_native


# More will be added as module features are expanded
CATEGORY_COMMANDS_ALL = {
    "Chassis": ["IndicatorLedOn", "IndicatorLedOff"],
}


def main():
    result = {}
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(required=True),
            command=dict(required=True, type='list', elements='str'),
            ioms=dict(type='list', elements='str'),
            baseuri=dict(),
            username=dict(required=True),
            password=dict(required=True, no_log=True),
            timeout=dict(type='int', default=10)
        ),
        supports_check_mode=True
    )

    category = module.params['category']
    command_list = module.params['command']

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
    # ToDo: choose the best URL!
    # Build root URI(s)
    if module.params.get("baseuri") is not None:
        root_uris = ["https://" + module.params['baseuri']]
    else:
        root_uris = [
            "https://" + iom for iom in module.params['ioms']
        ]
    ocapi_utils = OcapiUtils(creds, root_uris, timeout, module)

    # Check that Category is valid
    if category not in CATEGORY_COMMANDS_ALL:
        module.fail_json(msg=to_native("Invalid Category '%s'. Valid Categories = %s" % (category, list(CATEGORY_COMMANDS_ALL.keys()))))

    # Check that all commands are valid
    for cmd in command_list:
        # Fail if even one command given is invalid
        if cmd not in CATEGORY_COMMANDS_ALL[category]:
            module.fail_json(msg=to_native("Invalid Command '%s'. Valid Commands = %s" % (cmd, CATEGORY_COMMANDS_ALL[category])))

    # Organize by Categories / Commands
    if category == "Chassis":
        led_commands = ["IndicatorLedOn", "IndicatorLedOff"]

        # Check if more than on led_command is present
        num_led_commands = sum([command in led_commands for command in command_list])
        if num_led_commands > 1:
            result = {'ret': False, 'msg': "Only one IndicatorLed command should be sent at a time."}
        else:
            for command in command_list:
                if command.startswith("IndicatorLed"):
                    result = ocapi_utils.manage_chassis_indicator_led(command)

    if result['ret'] is False:
        module.fail_json(msg=to_native(result['msg']))
    else:
        del result['ret']
        changed = result.get('changed', True)
        session = result.get('session', dict())
        module.exit_json(changed=changed,
                         session=session,
                         msg='Action was successful' if not module.check_mode else result.get(
                             'msg', "No action performed in check mode."
                         ))


if __name__ == '__main__':
    main()
