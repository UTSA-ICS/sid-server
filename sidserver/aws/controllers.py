# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import traceback

import datetime
import sys

#from keystoneclient.common import cms
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six

from sidserver.common import controller
from sidserver.common import dependency
from sidserver.common import wsgi
from sidserver import exception
from sidserver.i18n import _
from sidserver.models import token_model
from sidserver.token import provider

from sidserver.aws import aws_sip


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class AWS(wsgi.Application):

    ## manually creare a sid for a group of organizations
    ## manually create Core Project and Open Project
    ## maintain a list of organizations accounts
    ## maintain a list of organizations security admin users
    orgs = {"CPS":"934324332443", "SAWS":"042298307144"}
    orgs_admins = {"SecAdminCPS":"SecAdminCPS", "SecAdminSAWS":"SecAdminSAWS"}
    ## maintain a list of AWS accounts for sip creation
    sips_accounts = {"SIP1":{"AWS_ACCOUNT_NO":"652714115935", "SIP_MANAGER":{"AWS_ACCESS_KEY_ID":"AKIAJD7U6ZQK5LKB2XQQ", "AWS_ACCESS_SECRET_KEY":"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"}}, "SIP2":{"AWS_ACCOUNT_NO":"401991328752", "SIP_MANAGER":{"AWS_ACCESS_KEY_ID":"AKIAJOSJHXHCNBVWSGMA", "AWS_ACCESS_SECRET_KEY":"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"}}}


    # SID
    def login_aws_user(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In login_aws_user function. %%%%%%%%%%%%%%%%%%")
	#print("The CONTEXT IS --> ", context)
	#print("The query string IS --> ", context['query_string'])
	#print("The environment IS --> ", context['environment'])
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	#print("The openstack_parms IS --> ", context['environment']['openstack.params'])
	print("The AWS ACESS KEY IS --> ", context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID'])
	print("The AWS ACESS KEY ID IS --> ", context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY'])
	print("The AWS CUSTOMER IS --> ", context['environment']['openstack.params']['auth']['AWS_ACCOUNT'])
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        login = aws_sip.aws_login(aws_access_key_id, aws_access_secret_key)
        #traceback.print_stack()
        return login

    def user_get(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In controller get_user function. %%%%%%%%%%%%%%%%%%")
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key)
	print("response: ",response)
	print("")
        return response

    def user_create(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	user_name = context['environment']['openstack.params']['auth']['AWS_USER_NAME']
	path='/'
        response = aws_sip.user_create(aws_access_key_id, aws_access_secret_key, path, user_name)
	print("response: ",response)
	print("")
        return response

    def user_delete(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	user_name = context['environment']['openstack.params']['auth']['AWS_USER_NAME']
        response = aws_sip.user_delete(aws_access_key_id, aws_access_secret_key, user_name)
	print("response: ",response)
	print("")
        return response

    def policies_list(self, context, auth=None):
	#print("The openstack_parms IS --> ", context['environment']['openstack.params'])
	#print("The context environment IS --> ", context['environment'])
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	scope='Local'
	onlyattached=False
	path = "/"
	#marker=''
        response = aws_sip.policies_list(aws_access_key_id, aws_access_secret_key, scope, onlyattached, path)
	print("response: ",response)
	print("")
        return response

    def policy_get(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In controller get_policy function. %%%%%%%%%%%%%%%%%%")
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	policy_arn = context['environment']['openstack.params']['auth']['AWS_POLICY_ARN']
        response = aws_sip.policy_get(aws_access_key_id, aws_access_secret_key, policy_arn)
	print("response: ",response)
	print("")
        return response

    def policy_create(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In controller create_policy function. %%%%%%%%%%%%%%%%%%")
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	policy_name = context['environment']['openstack.params']['auth']['AWS_POLICY_NAME']
	#policy_name = "AssumeRoleTest"
        policy_doc = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"arn:aws:iam::*:*\"}]}"
        response = aws_sip.policy_create(aws_access_key_id, aws_access_secret_key, policy_name, policy_doc)
	print("response: ",response)
	print("")
        return response

    def policy_delete(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	policy_arn = context['environment']['openstack.params']['auth']['AWS_POLICY_ARN']
        response = aws_sip.policy_delete(aws_access_key_id, aws_access_secret_key, policy_arn)
	print("response: ",response)
	print("")
        return response

    def roles_list(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	path = "/"
	#marker=''
        response = aws_sip.roles_list(aws_access_key_id, aws_access_secret_key, path)
	print("response: ",response)
	print("")
        return response

    def role_get(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['AWS_ROLE_NAME']
        response = aws_sip.role_get(aws_access_key_id, aws_access_secret_key, role_name)
	print("response: ",response)
	print("")
        return response

    def role_create(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	path = "/"
	role_name = context['environment']['openstack.params']['auth']['AWS_ROLE_NAME']
	#role_name = "SIPadmin"
	assume_role_policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": [ \"arn:aws:iam::042298307144:root\", \"arn:aws:iam::934324332443:root\" ] }, \"Action\": \"sts:AssumeRole\" } ] }"
        response = aws_sip.role_create(aws_access_key_id, aws_access_secret_key, path, role_name, assume_role_policy_doc)
	print("response: ",response)
	print("")
        return response

    def role_delete(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['AWS_ROLE_NAME']
        response = aws_sip.role_delete(aws_access_key_id, aws_access_secret_key, role_name)
	print("response: ",response)
	print("")
        return response

    def attach_user_policy(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	user_name = context['environment']['openstack.params']['auth']['AWS_USER_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['AWS_POLICY_ARN']
        response = aws_sip.attach_user_policy(aws_access_key_id, aws_access_secret_key, user_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def detach_user_policy(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	user_name = context['environment']['openstack.params']['auth']['AWS_USER_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['AWS_POLICY_ARN']
        response = aws_sip.detach_user_policy(aws_access_key_id, aws_access_secret_key, user_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def attach_role_policy(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['AWS_ROLE_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['AWS_POLICY_ARN']
        response = aws_sip.attach_role_policy(aws_access_key_id, aws_access_secret_key, role_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def detach_role_policy(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['AWS_ROLE_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['AWS_POLICY_ARN']
        response = aws_sip.detach_role_policy(aws_access_key_id, aws_access_secret_key, role_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def sip_create(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	    
        ## verify the user
        user = aws_sip.user_get(aws_access_key_id, aws_access_secret_key)
        if (user == ""):
            print("The user doesn't exist!")
            return

	## pick up one AWS account for the sip
	sip_account_no = self.sips_accounts['SIP1']['AWS_ACCOUNT_NO']

	## get sip manager key
	manager_aws_access_key_id = self.sips_accounts['SIP1']['SIP_MANAGER']['AWS_ACCESS_KEY_ID']
	manager_aws_access_secret_key = self.sips_accounts['SIP1']['SIP_MANAGER']['AWS_ACCESS_SECRET_KEY']

	## create SIPadmin role and SIPmember role
	path = "/"
	role_name = "SIPadmin"
	#assume_role_policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": [ \"arn:aws:iam::042298307144:root\", \"arn:aws:iam::934324332443:root\" ] }, \"Action\": \"sts:AssumeRole\" } ] }"
	assume_role_policy_str_ini = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": [  "
	assume_role_policy_str_tai = " ] }, \"Action\": \"sts:AssumeRole\" } ] }"
	assume_role_policy_str = ""
	cnt = 0
	for index in range(len(member_orgs)-1):
	    assume_role_policy_str = assume_role_policy_str + "\"arn:aws:iam::" + member_orgs[index] + ":root\", "  
	    cnt = cnt + 1
	#print("index=", index)
	#print("cnt=", cnt)
	assume_role_policy_str = assume_role_policy_str + "\"arn:aws:iam::" + member_orgs[cnt] + ":root\""
	assume_role_policy_doc = assume_role_policy_str_ini + assume_role_policy_str + assume_role_policy_str_tai
	print("assume_role_policy_doc = ", assume_role_policy_doc)

        role = aws_sip.role_create(manager_aws_access_key_id, manager_aws_access_secret_key, path, role_name, assume_role_policy_doc)

	## attach policy to SIPadmin/SIPmember role
	policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        policy = aws_sip.attach_role_policy(manager_aws_access_key_id, manager_aws_access_secret_key, role_name, policy_arn)

        return 




