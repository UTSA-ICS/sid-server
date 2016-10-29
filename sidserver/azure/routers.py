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
from sidserver.azure import controllers


class Router(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        azure_controller = controllers.Azure()

	# SID 
        mapper.connect('/azure/azure_login',
                       controller=azure_controller,
                       action='login_azure_user',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/user_list',
                       controller=azure_controller,
                       action='user_list',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/user_get',
                       controller=azure_controller,
                       action='user_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/user_create',
                       controller=azure_controller,
                       action='user_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/user_delete',
                       controller=azure_controller,
                       action='user_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/policies_list',
                       controller=azure_controller,
                       action='policies_list',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/policy_get',
                       controller=azure_controller,
                       action='policy_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/policy_create',
                       controller=azure_controller,
                       action='policy_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/policy_delete',
                       controller=azure_controller,
                       action='policy_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/roles_list',
                       controller=azure_controller,
                       action='roles_list',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/role_get',
                       controller=azure_controller,
                       action='role_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/role_create',
                       controller=azure_controller,
                       action='role_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/role_delete',
                       controller=azure_controller,
                       action='role_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/attach_user_policy',
                       controller=azure_controller,
                       action='attach_user_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/detach_user_policy',
                       controller=azure_controller,
                       action='detach_user_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/attach_role_policy',
                       controller=azure_controller,
                       action='attach_role_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/detach_role_policy',
                       controller=azure_controller,
                       action='detach_role_policy',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/sip_create',
                       controller=azure_controller,
                       action='sip_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/sip_delete',
                       controller=azure_controller,
                       action='sip_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/sip_list',
                       controller=azure_controller,
                       action='sip_list',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/list_available_sips',
                       controller=azure_controller,
                       action='list_available_sips',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/sid_create',
                       controller=azure_controller,
                       action='sid_create',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/sid_delete',
                       controller=azure_controller,
                       action='sid_delete',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/sid_get',
                       controller=azure_controller,
                       action='sid_get',
                       conditions=dict(method=['POST']))
        mapper.connect('/azure/sip_get',
                       controller=azure_controller,
                       action='sip_get',
                       conditions=dict(method=['POST']))

