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

from sidserver.aws import aws_sip
from sidserver.aws.backends import sql


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class AWS(wsgi.Application):

    def __init__(self):
        self.Mysip = sql.SIPs()
        self.Mysid = sql.SIDs()

    ## manually creare a sid for a group of organizations
    ## manually create Core Project and Open Project
    ## maintain a list of organizations accounts
    ## maintain a list of organizations security admin users
    orgs = {"CPS":"934324332443", "SAWS":"042298307144"}
    orgs_admins = {"SecAdminCPS":"SecAdminCPS", "SecAdminSAWS":"SecAdminSAWS"}
    ## maintain a list of AWS accounts for sip creation
    #sips_accounts = {"SIP1":{"AWS_ACCOUNT_NO":"652714115935", "SIP_MANAGER":{"AWS_ACCESS_KEY_ID":"AKIAJD7U6ZQK5LKB2XQQ", "AWS_ACCESS_SECRET_KEY":"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"}}, "SIP2":{"AWS_ACCOUNT_NO":"401991328752", "SIP_MANAGER":{"AWS_ACCESS_KEY_ID":"AKIAJOSJHXHCNBVWSGMA", "AWS_ACCESS_SECRET_KEY":"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"}}}
    sips_accounts = {"Available":{"AWS_ACCOUNT_NO":["652714115935", "401991328752"]}, "Unavailable":{"AWS_ACCOUNT_NO":""}}


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
	org_name = context['environment']['openstack.params']['auth']['AWS_ACCOUNT']
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
	#print("member_orgs=", member_orgs)
	#print("members_in_sid=", members_in_sid)
	#print("flag=", flag)

        ## verify the sec_admin user
        user = aws_sip.user_get(aws_access_key_id, aws_access_secret_key)
        if (user == ""):
            print("The user doesn't exist!")
            return

	## get sec_admin org account number and sec_admin user name
	## e.g.: User ARN: arn:aws:iam::934324332443:user/SecAdmin
	sec_admin_name = user['User']['UserName']
	sec_admin_arn = user['User']['Arn']
	org_account_no = sec_admin_arn[13:24]
	print("")	
	print("sec_admin_name=", sec_admin_name)
	print("sec_admin_arn=", sec_admin_arn)
	print("org_account_no=", org_account_no)
	print("")	

	## pick up one available AWS account for the sip
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
	manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
	manager_aws_access_secret_key = "xNZ2HQqmXoOUJ2dJMmEdCcUjD2p4SJQfGA1HxLRy"

	## create SIPadmin/SIPmember roles for organizations in the Sip
	## e.g. role name is like SIPadminXXX/SIPmemberXXX, XXX is org name
	path = "/"
	for org in member_orgs:
	    ## SIPadminXXX roles:
	    role_name = "SIPadmin" + org
	    assume_role_policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::" + member_orgs[org] + ":user/SecAdmin\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc = ", assume_role_policy_doc)
            role = aws_sip.role_create(manager_aws_access_key_id, manager_aws_access_secret_key, path, role_name, assume_role_policy_doc)

	    ## create policies for SIPadmin roles
	    policy_name = "SIPadmin" + org
	    policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Sid\": \"AllowCPSSecAdminToUpdateAssumeRolePolicy\", \"Effect\": \"Allow\", \"Action\": [ \"iam:UpdateAssumeRolePolicy\", \"iam:GetRole\" ], \"Resource\": [ \"arn:aws:iam::" + sip_account_id + ":role/SIPmember" + org + "\" ] }, { \"Sid\": \"AllowCPSSecAdminToListUsers\", \"Effect\": \"Allow\", \"Action\": [ \"iam:ListUsers\" ], \"Resource\": [ \"arn:aws:iam::" + sip_account_id + ":user/\" ] }, { \"Sid\": \"AllowCPSSecAdminToListRoles\", \"Effect\": \"Allow\", \"Action\": [ \"iam:ListRoles\" ], \"Resource\": [ \"arn:aws:iam::" + sip_account_id + ":role/\" ] } ] }"
	    role_policy = aws_sip.policy_create(manager_aws_access_key_id, manager_aws_access_secret_key,policy_name, policy_doc)
	    print("SIPadmin role policy:", role_policy)
	    ## attach policy to SIPadmin roles
	    policy_arn = role_policy['Policy']['Arn']
            aws_sip.attach_role_policy(manager_aws_access_key_id, manager_aws_access_secret_key, role_name, policy_arn)

	    ## SIPmemberXXX roles:
	    role_name2 = "SIPmember" + org
	    assume_role_policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::" + member_orgs[org] + ":root\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc2 = ", assume_role_policy_doc2)
            role2 = aws_sip.role_create(manager_aws_access_key_id, manager_aws_access_secret_key, path, role_name2, assume_role_policy_doc2)

	    ## create policies for SIPmember roles
	    policy_name2 = "SIPmember" + org
	    policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\" } ] }"
	    role_policy2 = aws_sip.policy_create(manager_aws_access_key_id, manager_aws_access_secret_key,policy_name2, policy_doc2)
	    print("SIPmember role policy:", role_policy2)
	    ## attach policy to SIPadmin roles
	    policy_arn2 = role_policy2['Policy']['Arn']
            aws_sip.attach_role_policy(manager_aws_access_key_id, manager_aws_access_secret_key, role_name2, policy_arn2)
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
        ## update the sip account to an available AWS account
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
