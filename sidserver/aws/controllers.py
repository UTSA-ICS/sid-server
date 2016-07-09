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
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name)
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
	try:
	    sid = self.get_sid(sid_id)
	except exception.NotFound as e:
            raise exception.NotFound("Can't find the sid!")
	members_in_sid = sid['sid_members']
        #print("")
	#print("members_in_sid=", members_in_sid)
	#print("member_orgs=", member_orgs)
        #print("")
	if( member_orgs != members_in_sid ):
	    raise exception.NotFound("Sip member orgs dont match the sid members!")

        ## verify the sec_admin user
        try:
            response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
        except exception.NotFound as e:
            raise exception.NotFound("Can't find the user!")
        admin_user_arn =  response['User']['Arn']
        get_admin_org_no = admin_user_arn.split(':')[4]
	if( get_admin_org_no != member_orgs.get(org_name) ):
            raise exception.NotFound("The user org doesnt match with the member orgs!" )
	    return
        #print("")
        #print("member_orgs.get(org_name) = ", member_orgs.get(org_name))
        #print("")
	    
	## get sec_admin org account number and sec_admin user name
	## e.g.: User ARN: arn:aws:iam::934324332443:user/SecAdmin
	sec_admin_name = response['User']['UserName']
	sec_admin_arn = response['User']['Arn']
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
	manager_aws_access_secret_key = "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"

	## assume sip manager role in the Sip
	sip_manager_role_arn = "arn:aws:iam::" + sip_account_id + ":role/SIDmanager"
	role_session_name = "sip_manager"
	assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
	response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, sip_manager_role_arn, role_session_name, assume_role_policy)
	print("")	
	print("Assume role credentials, response=", response)	
	print("")	

	## get sip manager tempory key for assume role
	temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
	temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
	temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]
	print("")	
	print("temp_manager_aws_access_key_id=", temp_manager_aws_access_key_id)	
	print("temp_manager_aws_access_secret_key=", temp_manager_aws_access_secret_key)	
	print("temp_manager_aws_access_session_token=", temp_manager_aws_access_session_token)	
	print("")	

	## create SIPadmin/SIPmember roles for organizations in the Sip
	## e.g. role name is like SIPadminXXX/SIPmemberXXX, XXX is org name
	path = "/"
	for org in member_orgs:
	    ## SIPadminXXX roles:
	    role_name = "SIPadmin" + org
	    assume_role_policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::" + member_orgs[org] + ":user/SecAdmin\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc = ", assume_role_policy_doc)
            role = aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name, assume_role_policy_doc)

	    ## create policies for SIPadmin roles
	    policy_name = "SIPadmin" + org
	    policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Sid\": \"AllowCPSSecAdminToListRolesUsers\", \"Effect\": \"Allow\", \"Action\": [ \"iam:ListRoles\", \"iam:ListUsers\", \"iam:ListPolicies\", \"iam:GetPolicy\" ], \"Resource\": [ \"arn:aws:iam::*\"  ] }, { \"Sid\": \"AllowCPSSecAdminToUpdateAssumeRolePolicy\", \"Effect\": \"Allow\", \"Action\": [ \"iam:*\" ], \"Resource\": [ \"arn:aws:iam::" + sip_account_id + ":role/SIPmember" + org + "\" ] } ] }"
	    role_policy = aws_sip.policy_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key,temp_manager_aws_access_session_token, policy_name, policy_doc)
	    print("SIPadmin role policy:", role_policy)
	    ## attach policy to SIPadmin roles
	    policy_arn = role_policy['Policy']['Arn']
            aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)

	    ## SIPmemberXXX roles:
	    role_name2 = "SIPmember" + org
	    assume_role_policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::" + member_orgs[org] + ":user/SecAdmin\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc2 = ", assume_role_policy_doc2)
            role2 = aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name2, assume_role_policy_doc2)

	    ## create policies for SIPmember roles
	    policy_name2 = "SIPmember" + org
	    policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\" } ] }"
	    role_policy2 = aws_sip.policy_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key,temp_manager_aws_access_session_token, policy_name2, policy_doc2)
	    print("SIPmember role policy:", role_policy2)
	    ## attach policy to SIPmember roles
	    policy_arn2 = role_policy2['Policy']['Arn']
            aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name2, policy_arn2)

        return 

    def sip_delete(self, context, auth=None):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
        member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	sip_account_id = context['environment']['openstack.params']['auth']['SIP_ACCOUNT_ID']

        ## get info from admin user
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
        admin_user_arn =  response['User']['Arn']
        org_no = admin_user_arn.split(':')[4]
        print("")
        print("org_no = ", org_no)
        print("")

        ## get the sip
        try:
            sip = self.get_sip(sip_account_id)
        except exception.NotFound as e:
            raise exception.NotFound("Cannot find the sip!")
        if(sip['status'] == "0"):
            print("The sip doesn't exist!")
            return
        print("")
        print("sip=", sip)
        print("")
	sid_id = sip['sid_id']

        ## verify the membership of org/admin in the sip (check if admin org is in the sip members)
        get_sip_members = sip['sip_members']
        print("")
        print("get_sip_members=", get_sip_members)
        print("")
        # get admin org name
        get_admin_org_name = ""
        for key, value in get_sip_members.iteritems():
            print("key=", key)
            print("value=", value)
            if (value == org_no):
                get_admin_org_name = key
        org_name = get_admin_org_name
        print("")
        print("org_name=", org_name)
        print("")
        if( org_name == ""):
            print("Your org doesn't belong to the sip!")
            return

        # verify the set of member organizations
        try:
            sid = self.get_sid(sid_id)
        except exception.NotFound as e:
            raise exception.NotFound("Can't find the sid!")
        members_in_sid = sid['sid_members']
        #print("")
        #print("members_in_sid=", members_in_sid)
        #print("member_orgs=", member_orgs)
        #print("")
        if( member_orgs != members_in_sid ):
            raise exception.NotFound("Sip member orgs dont match the sid members!")

	### delete roles and policies in the sip AWS account
        ## get sip manager key
        manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
        manager_aws_access_secret_key = "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"

        ## assume sip manager role in the Sip
        sip_manager_role_arn = "arn:aws:iam::" + sip_account_id + ":role/SIDmanager"
        role_session_name = "sip_manager"
        assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
        response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, sip_manager_role_arn, role_session_name, assume_role_policy)
        print("")
        print("Assume role credentials, response=", response)
        print("")

        ## get sip manager tempory key for assume role
        temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
        temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
        temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]
        print("")
        print("temp_manager_aws_access_key_id=", temp_manager_aws_access_key_id)
        print("temp_manager_aws_access_secret_key=", temp_manager_aws_access_secret_key)
        print("temp_manager_aws_access_session_token=", temp_manager_aws_access_session_token)
        print("")

        ## verify the admin user in the sip
        # verify the admin user has a SIPadminOrg role in the sip
        role_name = "SIPadmin" + org_name
        response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
        admin_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("admin_assume_role_policy_doc=", admin_assume_role_policy_doc)
        print("")
        # get admin role principlas (admin user arn) in the role
        admin_principals_aws = admin_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
        print("admin_principals_aws=", admin_principals_aws)
        if (admin_principals_aws != admin_user_arn):
            print("The user is not an admin in the sip!")
            raise exception.NotFound("The user is not an admin in the sip!")
            return

        # list roles
        response = aws_sip.roles_list(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path="/")
        print("")
        print("response to roles_list=", response)
        print("")
        index = 0
        for role in response["Roles"]:
            role_arn = response["Roles"][index]["Arn"]
            role_name = role_arn.split('/')[1]
            index = index + 1
            print("")
            print("role_name=", role_name)
	    
            # delete roles
            if(role_name[0:3] == "SIP"):
		# get policy 
		policy_name = role_name
                print("")
                print("role_name=", role_name)
                print("policy_name=", policy_name)
		#response = aws_sip.role_policy_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_name)
        	#print("")
        	#print("response to roles_policy_get=", response)
        	#print("")
	        # detach policies from the role
		policy_arn = "arn:aws:iam::" + sip_account_id + ":policy/" + policy_name 
                print("policy_arn=", policy_arn)
		ref = aws_sip.detach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)
                print("")
                print("going to delete role: role_name=", role_name)
                ref = aws_sip.role_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)

	# list policies
	response = aws_sip.policies_list(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, scope="Local", onlyattached=False, path="/")
        print("")
	print("response to policy_list=", response)
        print("")

	index = 0
	for policy in response["Policies"]:
	    policy_name = response["Policies"][index]["PolicyName"] 
	    policy_arn = response["Policies"][index]["Arn"]
	    index = index + 1
            print("")
	    print("policy_name=", policy_name)
	    print("policy_arn=", policy_arn)
	    # delete policies
	    if(policy_name[0:3] == "SIP"):
                print("")
	        print("going to delete policy: policy_name=", policy_name)
		ref = aws_sip.policy_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, policy_arn)

        ## update the sip account to an available AWS account
	sip = {}
	sip['status'] = "0"
	sip['sip_members'] = {}
	sip['sip_account_id'] = sip_account_id
	sip['account_name'] = ""
	sip['sid_id'] = ""
	print("")	
	print("sip=", sip)	
	print("")	
        ref = self.update_sip(sip_account_id, sip)
	
	return 

    def user_add(self, context, auth=None):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	sip_account_id = context['environment']['openstack.params']['auth']['SIP_ACCOUNT_ID']
	user_name = context['environment']['openstack.params']['auth']['USER_NAME']

	## get info from admin user
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
	admin_user_arn =  response['User']['Arn']
	admin_user_name =  response['User']['UserName']
	org_no = admin_user_arn.split(':')[4]
	print("")
	print("org_no = ", org_no)
	print("")

	## get the sip 
	try:
            sip = self.get_sip(sip_account_id)
        except exception.NotFound as e:
            raise exception.NotFound(e)
	print("")
	print("sip = ", sip)
	print("")
	if(sip['status'] == "0"):
	    print("The sip doesn't exist!")
	    return

	## verify the membership of org/admin in the sip (check if admin org is in the sip members)
	get_sip_members = sip['sip_members']
	print("")
	print("get_sip_members=", get_sip_members)
	print("")
	# get admin org name 
	get_admin_org_name = ""
	for key, value in get_sip_members.iteritems():
	    print("key=", key)
	    print("value=", value)
	    if (value == org_no):
		get_admin_org_name = key
	org_name = get_admin_org_name
	print("")
	print("org_name=", org_name)
	print("")
	if( org_name == ""):
	    print("Your org doesn't belong to the sip!")
	    return

        ## verify the normal user
	try:
            response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name)
        except exception.NotFound as e:
            #raise exception.NotFound(e)
            raise exception.NotFound("Can't find the user!")
	#! we dont need to verify if the user is in the same org as the admin user, 
	#! because by default (giving keys) the admin user can only access to his own account

        ## get sip manager key
        manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
        manager_aws_access_secret_key = "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"

        ## assume sip manager role in the Sip
        sip_manager_role_arn = "arn:aws:iam::" + sip_account_id + ":role/SIDmanager"
        role_session_name = "sip_manager"
        assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
        response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, sip_manager_role_arn, role_session_name, assume_role_policy)
        print("")
        print("Assume role credentials, response=", response)
        print("")

        ## get sip manager tempory key for assume role
        temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
        temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
        temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]
        print("")
        print("temp_manager_aws_access_key_id=", temp_manager_aws_access_key_id)
        print("temp_manager_aws_access_secret_key=", temp_manager_aws_access_secret_key)
        print("temp_manager_aws_access_session_token=", temp_manager_aws_access_session_token)
        print("")

        ## verify the admin user in the sip
	# verify the admin user has a SIPadminOrg role in the sip
	role_name = "SIPadmin" + org_name
	response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	admin_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("admin_assume_role_policy_doc=", admin_assume_role_policy_doc)
        print("")
	# get admin role principlas aws in the role
	admin_principals_aws = admin_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
	print("admin_principals_aws=", admin_principals_aws)
	if (admin_principals_aws != admin_user_arn):
	    print("The user is not an admin in the sip!")
	    raise exception.NotFound("The user is not an admin in the sip!")
	    return

	### SecAdmin user add normal users to a Sip
        # Update SIPmember roles (delete the role, then re-create it)
	role_name = "SIPmember" + org_name
	path="/"
        print("")
        print("role_name=", role_name)
	# get the old trust relationship 
	response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	old_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("old_assume_role_policy_doc=", old_assume_role_policy_doc)
        print("")
	# get existing users/principlas aws (array) in the existing role
	if('Principal' in old_assume_role_policy_doc['Statement'][0]):
	    old_principals_aws = old_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
	else:
	    old_principals_aws = []
	print("old_principals_aws=", old_principals_aws)
	#print("type of old_principals_aws=", type(old_principals_aws))
	#print("length of old_principals_aws=", len(old_principals_aws))
	if type(old_principals_aws) is not list:
	    old_principals_aws = [old_principals_aws]
	    #print("old_principals_aws=", old_principals_aws)
	# get a new user/principla aws for the new policy
	new_principals_aws_str = "arn:aws:iam::" + org_no + ":user/" + user_name
	new_principals_aws = [new_principals_aws_str] 
	print("new_principals_aws=", new_principals_aws)
	#print("type of new_principals_aws=", type(new_principals_aws))
	# create the new trust relationship policy (assume_role_policy_doc)
	#assume_role_policy_doc_body_list = old_principals_aws + new_principals_aws
	assume_role_policy_doc_body_list = list(set(old_principals_aws + new_principals_aws))
        print("assume_role_policy_doc_body_list = ", assume_role_policy_doc_body_list)
	new_list = []
	for element in assume_role_policy_doc_body_list:
	    new_element = '\"' + element + '\"'
	    new_list = new_list + [new_element]
	assume_role_policy_doc_body = '[' + ','.join(new_list) + ']'
        print("assume_role_policy_doc_body = ", assume_role_policy_doc_body)
	assume_role_policy_doc_head = "{ \"Version\": \"2012-10-17\", \"Statement\": [ {  \"Action\": \"sts:AssumeRole\", \"Effect\": \"Allow\", \"Principal\": {\"AWS\": "
	assume_role_policy_doc_tail = " } } ] }"
	assume_role_policy_doc = assume_role_policy_doc_head + assume_role_policy_doc_body + assume_role_policy_doc_tail
        print("assume_role_policy_doc = ", assume_role_policy_doc)
        # delete the old SIPmemberXXX role
	# get policy 
	policy_name = role_name
        print("")
        print("policy_name=", policy_name)
	# detach policy from the old role
	policy_arn = "arn:aws:iam::" + sip_account_id + ":policy/" + policy_name 
        print("policy_arn=", policy_arn)
	ref = aws_sip.detach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)
        print("")
        print("going to delete role: role_name=", role_name)
        ref = aws_sip.role_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	# re-create the SIPmemberXXX role 
        aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name, assume_role_policy_doc)

        ## attach policy to the SIPmemberXXX role
        aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)

	return 

    def user_remove(self, context, auth=None):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	sip_account_id = context['environment']['openstack.params']['auth']['SIP_ACCOUNT_ID']
	user_name = context['environment']['openstack.params']['auth']['USER_NAME']

	### get info and verifications
	## get info from admin user
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
	admin_user_arn =  response['User']['Arn']
	admin_user_name =  response['User']['UserName']
	org_no = admin_user_arn.split(':')[4]
	print("")
	print("org_no = ", org_no)
	print("")

	## get the sip 
	try:
            sip = self.get_sip(sip_account_id)
        except exception.NotFound as e:
            raise exception.NotFound(e)
	print("")
	print("sip = ", sip)
	print("")
	if(sip['status'] == "0"):
	    print("The sip doesn't exist!")
	    return

	## verify the membership of org/admin in the sip (check if admin org is in the sip members)
	get_sip_members = sip['sip_members']
	print("")
	print("get_sip_members=", get_sip_members)
	print("")
	# get admin org name 
	get_admin_org_name = ""
	for key, value in get_sip_members.iteritems():
	    print("key=", key)
	    print("value=", value)
	    if (value == org_no):
		get_admin_org_name = key
	org_name = get_admin_org_name
	print("")
	print("org_name=", org_name)
	print("")
	if( org_name == ""):
	    print("Your org doesn't belong to the sip!")
	    return

        ## verify the normal user
	try:
            response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name)
        except exception.NotFound as e:
            raise exception.NotFound(e)

	### start removing the user
        ## get sip manager key
        manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
        manager_aws_access_secret_key = "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"

        ## assume sip manager role in the Sip
        sip_manager_role_arn = "arn:aws:iam::" + sip_account_id + ":role/SIDmanager"
        role_session_name = "sip_manager"
        assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
        response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, sip_manager_role_arn, role_session_name, assume_role_policy)
        print("")
        print("Assume role credentials, response=", response)
        print("")

        ## get sip manager tempory key for assume role
        temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
        temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
        temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]
        print("")
        print("temp_manager_aws_access_key_id=", temp_manager_aws_access_key_id)
        print("temp_manager_aws_access_secret_key=", temp_manager_aws_access_secret_key)
        print("temp_manager_aws_access_session_token=", temp_manager_aws_access_session_token)
        print("")

        ## verify the admin user in the sip
	# verify the admin user has a SIPadminOrg role in the sip
	role_name = "SIPadmin" + org_name
	response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	admin_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("admin_assume_role_policy_doc=", admin_assume_role_policy_doc)
        print("")
	# get admin role principlas (admin user arn) in the role
	admin_principals_aws = admin_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
	print("admin_principals_aws=", admin_principals_aws)
	if (admin_principals_aws != admin_user_arn):
	    print("The user is not an admin in the sip!")
	    raise exception.NotFound("The user is not an admin in the sip!")
	    return

	### SecAdmin user remove normal users from a Sip
        # Update SIPmember roles (delete the role, then re-create it)
	role_name = "SIPmember" + org_name
	path="/"
        print("")
        print("role_name=", role_name)
	# get the old trust relationship 
	response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	old_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("old_assume_role_policy_doc=", old_assume_role_policy_doc)
        print("")
	# get existing users/principlas aws (array) in the existing role
	if('Principal' in old_assume_role_policy_doc['Statement'][0]):
	    old_principals_aws = old_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
	else:
	    old_principals_aws = []
	print("old_principals_aws=", old_principals_aws)
	if type(old_principals_aws) is not list:
	    old_principals_aws = [old_principals_aws]
	    #print("old_principals_aws=", old_principals_aws)
	# find the user/principle in the trust relationship 
	new_principals_aws = []
	for element in old_principals_aws:
	    if(user_name in element):
		print("User %s will be removed from the sip!", user_name)
	    else:
		new_principals_aws.extend([element])
		#new_principals_aws = new_principals_aws + [element]
		print("new_principals_aws=", new_principals_aws)
		
	print("$$$new_principals_aws=", new_principals_aws)
	if(len(new_principals_aws) == 1):
	    assume_role_policy_doc_body = '\"' + new_principals_aws[0]  + '\"' 
	else:
	    new_list = []
	    for element in new_principals_aws:
	        new_element = '\"' + element + '\"'
	        new_list = new_list + [new_element]
	    assume_role_policy_doc_body = '[' + ','.join(new_list) + ']'
	# create the new trust relationship policy (assume_role_policy_doc)
        print("assume_role_policy_doc_body = ", assume_role_policy_doc_body)
	assume_role_policy_doc_head = "{ \"Version\": \"2012-10-17\", \"Statement\": [ {  \"Action\": \"sts:AssumeRole\", \"Effect\": \"Allow\", \"Principal\": {\"AWS\": "
	assume_role_policy_doc_tail = " } } ] }"
	assume_role_policy_doc = assume_role_policy_doc_head + assume_role_policy_doc_body + assume_role_policy_doc_tail
        print("assume_role_policy_doc = ", assume_role_policy_doc)
        # delete the old SIPmemberXXX role
	# get policy 
	policy_name = role_name
        print("")
        print("policy_name=", policy_name)
	# detach policy from the old role
	policy_arn = "arn:aws:iam::" + sip_account_id + ":policy/" + policy_name 
        print("policy_arn=", policy_arn)
	ref = aws_sip.detach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)
        print("")
        print("going to delete role: role_name=", role_name)
        ref = aws_sip.role_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	# re-create the SIPmemberXXX role 
        aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name, assume_role_policy_doc)

        ## attach policy to the SIPmemberXXX role
        aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)

	return 


    def sip_get(self, context, auth=None):
	sip_account_id = context['environment']['openstack.params']['auth']['SIP_ACCOUNT_ID']
	sip = self.get_sip(sip_account_id)
	#print("")	
	#print("sip=", sip)	
	#print("")	
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
	print("")	
	print("sid=", sid)	
	print("")	
	sid = self.Mysid.add_sid(sid)	
	return sid

    def sid_delete(self, context, auth=None):
	sid_id = context['environment']['openstack.params']['auth']['SID_ID']
	sid = self.Mysid.delete_sid(sid_id)
	return 

    def sid_get(self, context, auth=None):
	sid_id = context['environment']['openstack.params']['auth']['SID_ID']
	#sid = self.get_sid(sid_id)
	sid = self.Mysid.get_sid(sid_id)
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

    def get_sid(self, sid_id):
        ret = self.Mysid.get_sid(sid_id)
        return ret

    def delete_sid(self, sid_id):
        ret = self.Mysid.delete_sid(sid_id)
        return ret
