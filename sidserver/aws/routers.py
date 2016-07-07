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
        mapper.connect('/aws/user_get',
                       controller=aws_controller,
                       action='user_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/user_create',
                       controller=aws_controller,
                       action='user_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/user_delete',
                       controller=aws_controller,
                       action='user_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/policies_list',
                       controller=aws_controller,
                       action='policies_list',
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
        mapper.connect('/aws/roles_list',
                       controller=aws_controller,
                       action='roles_list',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/role_get',
                       controller=aws_controller,
                       action='role_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/role_create',
                       controller=aws_controller,
                       action='role_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/role_delete',
                       controller=aws_controller,
                       action='role_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/attach_user_policy',
                       controller=aws_controller,
                       action='attach_user_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/detach_user_policy',
                       controller=aws_controller,
                       action='detach_user_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/attach_role_policy',
                       controller=aws_controller,
                       action='attach_role_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/detach_role_policy',
                       controller=aws_controller,
                       action='detach_role_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/sip_create',
                       controller=aws_controller,
                       action='sip_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/sip_delete',
                       controller=aws_controller,
                       action='sip_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/sip_list',
                       controller=aws_controller,
                       action='sip_list',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/list_available_sips',
                       controller=aws_controller,
                       action='list_available_sips',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/sid_create',
                       controller=aws_controller,
                       action='sid_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/sid_delete',
                       controller=aws_controller,
                       action='sid_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/sid_get',
                       controller=aws_controller,
                       action='sid_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/sip_get',
                       controller=aws_controller,
                       action='sip_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/user_add',
                       controller=aws_controller,
                       action='user_add',
                       conditions=dict(method=['POST']))
        mapper.connect('/aws/user_remove',
                       controller=aws_controller,
                       action='user_remove',
                       conditions=dict(method=['POST']))

