# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from sidserver.common import wsgi
from sidserver.aws import controllers


class Router(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        aws_controller = controllers.AWS()

	# SID 
        mapper.connect('/aws/user_login',
                       controller=aws_controller,
                       action='login_aws_user',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/create_sip',
                       controller=aws_controller,
                       action='sip_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/get_user',
                       controller=aws_controller,
                       action='get_user',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/get_policy',
                       controller=aws_controller,
                       action='get_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/policy_get',
                       controller=aws_controller,
                       action='policy_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/policy_create',
                       controller=aws_controller,
                       action='policy_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/policy_delete',
                       controller=aws_controller,
                       action='policy_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/role_create',
                       controller=aws_controller,
                       action='role_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/attach_user_policy',
                       controller=aws_controller,
                       action='attach_user_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/attach_role_policy',
                       controller=aws_controller,
                       action='attach_role_policy',
                       conditions=dict(method=['POST']))

