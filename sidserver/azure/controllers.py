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


import random
import string
import traceback
import datetime
import sys
import six

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils

from sidserver.common import wsgi
from sidserver import exception
from sidserver.i18n import _

from sidserver.azure import azure_sip
from sidserver.azure.backends import sql
from azure.common.credentials import UserPassCredentials
from azure.mgmt.authorization import AuthorizationManagementClient, AuthorizationManagementClientConfiguration
from azure.mgmt.redis.models import Sku, RedisCreateOrUpdateParameters
from azure.graphrbac import GraphRbacManagementClient, GraphRbacManagementClientConfiguration
from azure.graphrbac.models import UserCreateParameters, UserCreateParametersPasswordProfile



CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Azure(wsgi.Application):

    def __init__(self):
        self.Mysip = sql.AzureSIPs()
        self.Mysid = sql.AzureSIDs()

    graphrbac_client = None
    authorization_client = None
    #def setup_client(self):
    def setup_client(self, context):
        #user_id = context['environment']['openstack.params']['auth']['credentials']['ADMIN_USER_ID']
        #user_pw= context['environment']['openstack.params']['auth']['credentials']['ADMIN_USER_PW']
        #azure_tenant_id= str(context['environment']['openstack.params']['auth']['AZURE_TENANT_ID'])
        subscription_id= str(context['environment']['openstack.params']['auth']['SUBSCRIPTION_ID'])
        credentials = UserPassCredentials(
            "SIDmanager@SIDdomain.onmicrosoft.com",    # Your new user
            "XXXX",  # Your password
	    #user_id,
	    #user_pw,
            resource = "https://graph.windows.net"
        )
        azure_tenant_id = "cc27778d-9be"
        self.graphrbac_client = GraphRbacManagementClient(
            GraphRbacManagementClientConfiguration(
                credentials,
                azure_tenant_id
            )
        )

        #subscription_id = '1beafe45-ce54'
        self.authorization_client = AuthorizationManagementClient(
            AuthorizationManagementClientConfiguration(
                credentials,
                subscription_id
            )
        )

    def login_azure_user(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In login_azure_user function. %%%%%%%%%%%%%%%%%%")
	self.setup_client(context)
        azure_sip.azure_login(self.authorization_client)
        return 

    def user_list(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In controller user_list function. %%%%%%%%%%%%%%%%%%")
	self.setup_client(context)
        response = azure_sip.user_list(self.graphrbac_client)
	print("response: ",response)
	print("")
        return 

    def user_get(self, context, auth=None):
	self.setup_client(context)
	user_id = context['environment']['openstack.params']['auth']['AZURE_USER_ID']
        response = azure_sip.user_get(self.graphrbac_client, user_id)
	print("response: ",response)
	print("")
        return 

    def user_create(self, context, auth=None):
	self.setup_client(context)
	parameters = context['environment']['openstack.params']['auth']['parameters']
        response = azure_sip.user_create(self.graphrbac_client, parameters)
	print("response: ",response)
	print("")
        return 

    def user_delete(self, context, auth=None):
	self.setup_client(context)
	user_id = context['environment']['openstack.params']['auth']['AZURE_USER_ID']
        response = azure_sip.user_delete(self.graphrbac_client, user_id)
	print("response: ",response)
	print("")
        return 

    def policies_list(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	scope='Local'
	onlyattached=False
	path = "/"
        response = azure_sip.policies_list(azure_access_key_id, azure_access_secret_key, scope, onlyattached, path)
	print("response: ",response)
	print("")
        return response

    def policy_get(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In controller get_policy function. %%%%%%%%%%%%%%%%%%")
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	policy_arn = context['environment']['openstack.params']['auth']['Azure_POLICY_ARN']
        response = azure_sip.policy_get(azure_access_key_id, azure_access_secret_key, policy_arn)
	print("response: ",response)
	print("")
        return response

    def policy_create(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In controller create_policy function. %%%%%%%%%%%%%%%%%%")
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	policy_name = context['environment']['openstack.params']['auth']['Azure_POLICY_NAME']
        policy_doc = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"arn:azure:iam::*:*\"}]}"
        response = azure_sip.policy_create(azure_access_key_id, azure_access_secret_key, policy_name, policy_doc)
	print("response: ",response)
	print("")
        return response

    def policy_delete(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	policy_arn = context['environment']['openstack.params']['auth']['Azure_POLICY_ARN']
        response = azure_sip.policy_delete(azure_access_key_id, azure_access_secret_key, policy_arn)
	print("response: ",response)
	print("")
        return response

    def roles_list(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	path = "/"
        response = azure_sip.roles_list(azure_access_key_id, azure_access_secret_key, path)
	print("response: ",response)
	print("")
        return response

    def role_get(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['Azure_ROLE_NAME']
        response = azure_sip.role_get(azure_access_key_id, azure_access_secret_key, role_name)
	print("response: ",response)
	print("")
        return response

    def role_create(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	path = "/"
	role_name = context['environment']['openstack.params']['auth']['Azure_ROLE_NAME']
	assume_role_policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"Azure\": [ \"arn:azure:iam::042298307144:root\", \"arn:azure:iam::934324332443:root\" ] }, \"Action\": \"sts:AssumeRole\" } ] }"
        response = azure_sip.role_create(azure_access_key_id, azure_access_secret_key, path, role_name, assume_role_policy_doc)
	print("response: ",response)
	print("")
        return response

    def role_delete(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['Azure_ROLE_NAME']
        response = azure_sip.role_delete(azure_access_key_id, azure_access_secret_key, role_name)
	print("response: ",response)
	print("")
        return response

    def attach_user_policy(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	user_name = context['environment']['openstack.params']['auth']['Azure_USER_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['Azure_POLICY_ARN']
        response = azure_sip.attach_user_policy(azure_access_key_id, azure_access_secret_key, user_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def detach_user_policy(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	user_name = context['environment']['openstack.params']['auth']['Azure_USER_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['Azure_POLICY_ARN']
        response = azure_sip.detach_user_policy(azure_access_key_id, azure_access_secret_key, user_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def attach_role_policy(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['Azure_ROLE_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['Azure_POLICY_ARN']
        response = azure_sip.attach_role_policy(azure_access_key_id, azure_access_secret_key, role_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def detach_role_policy(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	role_name = context['environment']['openstack.params']['auth']['Azure_ROLE_NAME']
	policy_arn = context['environment']['openstack.params']['auth']['Azure_POLICY_ARN']
        response = azure_sip.detach_role_policy(azure_access_key_id, azure_access_secret_key, role_name, policy_arn)
	print("response: ",response)
	print("")
        return response

    def sip_create(self, context, auth=None):
	azure_access_key_id = context['environment']['openstack.params']['auth']['Azure_ACCESS_KEY_ID']
	azure_access_secret_key = context['environment']['openstack.params']['auth']['Azure_ACCESS_SECRET_KEY']
	org_name = context['environment']['openstack.params']['auth']['Azure_ACCOUNT']
	member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	sip_name = context['environment']['openstack.params']['auth']['SIP_NAME']
	sid_id = context['environment']['openstack.params']['auth']['SID_ID']
	    
	# verify the set of member organizations
	sid = self.get_sid(sid_id)
	members_in_sid = sid['sid_members']
	flag = 0
	for org in member_orgs:
	    if org not in members_in_sid:
		flag = 1
		print("")
		print("Organization " + org + " doesn't belong to the SID")
		print("")

        ## verify the sec_admin user
        user = azure_sip.user_get(azure_access_key_id, azure_access_secret_key)
        if (user == ""):
            print("The user doesn't exist!")
            return

	## get sec_admin org account number and sec_admin user name
	## e.g.: User ARN: arn:azure:iam::934324332443:user/SecAdmin
	sec_admin_name = user['User']['UserName']
	sec_admin_arn = user['User']['Arn']
	org_account_no = sec_admin_arn[13:24]

	## pick up one available Azure account for the sip
	sip_account_id = self.get_one_available_sip()
	sip = {}
	sip['status'] = "1"
	sip['sip_members'] = member_orgs
	sip['sip_account_id'] = sip_account_id
	sip['account_name'] = sip_name
	sip['sid_id'] = sid_id
	print("")	
	print("sip=", sip)	
	print("")	

	## create a sip (update the sip account)
	ref = self.update_sip(sip_account_id, sip)
	
	## get sip manager key
	manager_azure_access_key_id = "AKIAJLXXXX"
	manager_azure_access_secret_key = "xNZ2HQqmXoOUJ2dJMmEdCXXXX"

	## create SIPadmin/SIPmember roles for organizations in the Sip
	## e.g. role name is like SIPadminXXX/SIPmemberXXX, XXX is org name
	path = "/"
	for org in member_orgs:
	    ## SIPadminXXX roles:
	    role_name = "SIPadmin" + org
	    assume_role_policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"Azure\": \"arn:azure:iam::" + member_orgs[org] + ":user/SecAdmin\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc = ", assume_role_policy_doc)
            role = azure_sip.role_create(manager_azure_access_key_id, manager_azure_access_secret_key, path, role_name, assume_role_policy_doc)

	    ## create policies for SIPadmin roles
	    policy_name = "SIPadmin" + org
	    policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Sid\": \"AllowCPSSecAdminToUpdateAssumeRolePolicy\", \"Effect\": \"Allow\", \"Action\": [ \"iam:UpdateAssumeRolePolicy\", \"iam:GetRole\" ], \"Resource\": [ \"arn:azure:iam::" + sip_account_id + ":role/SIPmember" + org + "\" ] }, { \"Sid\": \"AllowCPSSecAdminToListUsers\", \"Effect\": \"Allow\", \"Action\": [ \"iam:ListUsers\" ], \"Resource\": [ \"arn:azure:iam::" + sip_account_id + ":user/\" ] }, { \"Sid\": \"AllowCPSSecAdminToListRoles\", \"Effect\": \"Allow\", \"Action\": [ \"iam:ListRoles\" ], \"Resource\": [ \"arn:azure:iam::" + sip_account_id + ":role/\" ] } ] }"
	    role_policy = azure_sip.policy_create(manager_azure_access_key_id, manager_azure_access_secret_key,policy_name, policy_doc)
	    print("SIPadmin role policy:", role_policy)
	    ## attach policy to SIPadmin roles
	    policy_arn = role_policy['Policy']['Arn']
            azure_sip.attach_role_policy(manager_azure_access_key_id, manager_azure_access_secret_key, role_name, policy_arn)

	    ## SIPmemberXXX roles:
	    role_name2 = "SIPmember" + org
	    assume_role_policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"Azure\": \"arn:azure:iam::" + member_orgs[org] + ":root\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc2 = ", assume_role_policy_doc2)
            role2 = azure_sip.role_create(manager_azure_access_key_id, manager_azure_access_secret_key, path, role_name2, assume_role_policy_doc2)

	    ## create policies for SIPmember roles
	    policy_name2 = "SIPmember" + org
	    policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\" } ] }"
	    role_policy2 = azure_sip.policy_create(manager_azure_access_key_id, manager_azure_access_secret_key,policy_name2, policy_doc2)
	    print("SIPmember role policy:", role_policy2)
	    ## attach policy to SIPadmin roles
	    policy_arn2 = role_policy2['Policy']['Arn']
            azure_sip.attach_role_policy(manager_azure_access_key_id, manager_azure_access_secret_key, role_name2, policy_arn2)
        return 

    def sip_delete(self, context, auth=None):
	#member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	sip_account_id = context['environment']['openstack.params']['auth']['SIP_ACCOUNT_ID']
	## get the sip 
	sip = {}
	sip['status'] = "0"
	sip['sip_members'] = ""
	sip['sip_account_id'] = sip_account_id
	sip['account_name'] = ""
	print("")	
	print("sip=", sip)	
	print("")	
        ## update the sip account to an available Azure account
        ref = self.update_sip(sip_account_id, sip)
	return ref

    def sip_get(self, context, auth=None):
	sip_account_id = context['environment']['openstack.params']['auth']['SIP_ACCOUNT_ID']
	sip = self.get_sip(sip_account_id)
	print("")	
	print("sip=", sip)	
	print("")	
	return sip

    def sid_create(self, context, auth=None):
	member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	sid_name = context['environment']['openstack.params']['auth']['SID_NAME']
	## add a sid to SIDs table
	sid = {}
	random_string = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
	sid['sid_id'] = random_string 
	sid['sid_name'] = sid_name
	sid['sid_members'] = member_orgs
	sid['status'] = "1"
	print("")	
	print("sid=", sid)	
	print("")	
	sid = self.add_sid(sid)	
	return sid

    def sid_delete(self, context, auth=None):
	sid_id = context['environment']['openstack.params']['auth']['SID_ID']
	self.delete_sid(sid_id)
	return 

    def sid_get(self, context, auth=None):
	sid_id = context['environment']['openstack.params']['auth']['SID_ID']
	sid = self.get_sid(sid_id)
	print("")	
	print("sid=", sid)	
	print("")	
	return sid

    def get_one_available_sip(self):
        accounts = self.Mysip.list_sips()
	available_account = ""
	for element in accounts:
	    if element['status'] == "0":
		available_account = element
		available_sip_account_id = element['sip_account_id']
		break
	    print("current account:", element)
	print("available_account:", available_account)
	print("available_sip_account_id:", available_sip_account_id)
	return available_sip_account_id

    def update_sip(self, sip_account_id, sip):
        return self.Mysip.update_sip(sip_account_id, sip)

    def sip_list(self, context):
        accounts = self.Mysip.list_sips()
        return accounts

    # list all available sips
    def list_available_sips(self, context):
	sips = self.Mysip.list_available_sips()
	print("")	
	print("Available sips=", sips)	
	print("")	
	return sips

    def add_sip(self, sip):
        ret = self.Mysip.add_sip(sip)
        return ret

    def get_sip(self, sip_account_id):
        ret = self.Mysip.get_sip(sip_account_id)
        return ret

    def delete_sip(self, sip_account_id):
        return self.Mysip.delete_sip(sip_account_id)

    # end of sip part 

    def add_sid(self, sid):
        ret = self.Mysid.add_sid(sid)
        return ret

    def get_sid(self, sid_id):
        ret = self.Mysid.get_sid(sid_id)
        return ret

    def delete_sid(self, sid_id):
        return self.Mysid.delete_sid(sid_id)
