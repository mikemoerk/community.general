#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Western Digital Corporation
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: ocapi_info
short_description: Manages Out-Of-Band controllers using Open Composable API (OCAPI).
description:
  - Builds OCAPI URIs locally and sends them to remote OOB controllers to
    get information back.
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
  jobUri:
    description:
      -URI for fetching a job status.
    type: str


author: "Mike Moerk (@mikemoerk)"
'''

EXAMPLES = '''
  - name: Get job status
    community.general.ocapi_info:
      category: Status
      command: JobStatus
      ioms: "{{ ioms }}"
      statusMonitor: https://ioma.wdc.com/Storage/Devices/openflex-data24-usalp03020qb0003/Jobs/FirmwareUpdate/
      username: "{{ username }}"
      password: "{{ password }}"
'''

RETURN = '''
msg:
    description: Message with action result or error description
    returned: always
    type: str
    sample: "Action was successful"

percentComplete:
    description: Percent complete of the relevant operation.  Applies to JobStatus command.
    returned: when supported
    type: int
    sample: 99

operationStatus:
    description: Status of the relevant operation.  Applies to JobStatus command.  See OCAPI documentation for details.
    returned: when supported
    type: str
    sample: "Activate needed"

operationStatusId:
    description: Integer value of status (corresponds to operationStatus).  Applies to JobStatus command.  See OCAPI documentation for details.
    returned: when supported
    type: int
    sample: 65540

operationHealth:
    description: Health of the operation.  Applies to JobStatus command.  See OCAPI documentation for details.
    returned: when supported
    type: str
    sample: "OK"

operationHealthId:
    description: Integer value for health of the operation (corresponds to operationHealth). Applies to JobStatus command. See OCAPI documentation for details.
    returned: when supported
    type: str
    sample: "OK"

details:
    description: Details of the relevant operation.  Applies to statusMonitor command.
    returned: when supported
    type: list
    elements: str

status:
    description: Dict containing status information.  See OCAPI documentation for details.
    returned: when supported
    type: dict
    sample: {
        "Details": [
            "None"
        ],
        "Health": [
            {
                "ID": 5,
                "Name": "OK"
            }
        ],
        "State": {
            "ID": 16,
            "Name": "In service"
        }
    }

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.general.plugins.module_utils.ocapi_utils import OcapiUtils
from ansible.module_utils.common.text.converters import to_native

# More will be added as module features are expanded
CATEGORY_COMMANDS_ALL = {
    "Status": ["JobStatus", "SystemStatus"]
}


def main():
    result = {}
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(required=True),
            command=dict(required=True, type='str'),
            jobUri=dict(type='str'),
            ioms=dict(type='list', elements='str'),
            baseuri=dict(),
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
    if category == "Status":
        if command == "JobStatus":
            if module.params.get("jobUri") is None:
                module.fail_json(msg=to_native(
                    "jobUri required for JobStatus command."))
            result = ocapi_utils.get_job_status(module.params['jobUri'])
        elif command == "SystemStatus":
            result = ocapi_utils.get_system_status()

    if result['ret'] is False:
        module.fail_json(msg=to_native(result['msg']))
    else:
        del result['ret']
        changed = False
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
