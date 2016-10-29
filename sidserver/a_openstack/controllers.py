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


class OpenStack(wsgi.Application):

    def __init__(self):
        self.Mysip = sql.SIPs()
        self.Mysid = sql.SIDs()

    # SID
    def login_aws_user(self, context, auth=None):
        print("%%%%%%%%%%%%%%%%%%% In login_aws_user function. %%%%%%%%%%%%%%%%%%")
	#print("The CONTEXT IS --> ", context)
	#print("The query string IS --> ", context['query_string'])
	#print("The environment IS --> ", context['environment'])
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	#print("The openstack_parms IS --> ", context['environment']['openstack.params'])
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

    def project_create(self, context, auth=None):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	project_name = context['environment']['openstack.params']['auth']['PROJECT_NAME']
        #response = aws_sip.user_create(aws_access_key_id, aws_access_secret_key, path, user_name)
	#print("response: ",response)
	#print("")
        identity_client = self.app.client_manager.identity

        enabled = True
        if parsed_args.disable:
            enabled = False
        kwargs = {}
        if parsed_args.property:
            kwargs = parsed_args.property.copy()

        project = identity_client.tenants.create(
            parsed_args.name,
            description=parsed_args.description,
            enabled=enabled,
            **kwargs
        )

        info = {}
        info.update(project._info)
        return zip(*sorted(six.iteritems(info)))

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
	sip_account_id = context['environment']['openstack.params']['auth']['SIP_ACCOUNT_ID']
	ref = self._sip_delete(sip_account_id, context)
	return ref

    def _sip_delete(self, sip_account_id, context):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
        member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']

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


    def cp_user_add(self, context, auth=None):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	cp_account_id = context['environment']['openstack.params']['auth']['CP_ACCOUNT_ID']
	user_name = context['environment']['openstack.params']['auth']['USER_NAME']

	## get info from admin user
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
	admin_user_arn =  response['User']['Arn']
	admin_user_name =  response['User']['UserName']
	org_no = admin_user_arn.split(':')[4]
	print("")
	print("org_no = ", org_no)
	print("")

	## get the cp 
	try:
            cp = self.get_sip(cp_account_id)
        except exception.NotFound as e:
            raise exception.NotFound(e)
	if(cp['status'] == "0"):
	    print("The cp doesn't exist!")
	    return

	## verify the membership of org/admin in the cp (check if admin org is in the cp members)
	get_cp_members = cp['sip_members']
	# get admin org name 
	get_admin_org_name = ""
	for key, value in get_cp_members.iteritems():
	    if (value == org_no):
		get_admin_org_name = key
	org_name = get_admin_org_name
	if( org_name == ""):
	    print("Your org doesn't belong to the cp!")
	    return

        ## verify the normal user
	try:
            response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name)
        except exception.NotFound as e:
            #raise exception.NotFound(e)
            raise exception.NotFound("Can't find the user!")
	#! we dont need to verify if the user is in the same org as the admin user, 
	#! because by default (giving keys) the admin user can only access to his own account

        ## get cp manager key
        manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
        manager_aws_access_secret_key = "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"

        ## assume cp manager role in the Sip
        cp_manager_role_arn = "arn:aws:iam::" + cp_account_id + ":role/SIDmanager"
        role_session_name = "cp_manager"
        assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
        response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, cp_manager_role_arn, role_session_name, assume_role_policy)

        ## get cp manager tempory key for assume role
        temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
        temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
        temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]

        ## verify the admin user in the cp
	# verify the admin user has a CPadminOrg role in the cp
	role_name = "CPadmin" + org_name
	response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	admin_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("admin_assume_role_policy_doc=", admin_assume_role_policy_doc)
        print("")
	# get admin role principlas aws in the role
	admin_principals_aws = admin_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
	print("admin_principals_aws=", admin_principals_aws)
	if (admin_principals_aws != admin_user_arn):
	    print("The user is not an admin in the cp!")
	    raise exception.NotFound("The user is not an admin in the cp!")
	    return

	### SecAdmin user add normal users to a Sip
        # Update CPmember roles (delete the role, then re-create it)
	role_name = "CPmember" + org_name
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
        # delete the old CPmemberXXX role
	# get policy 
	policy_name = role_name
        print("")
        print("policy_name=", policy_name)
	# detach policy from the old role
	policy_arn = "arn:aws:iam::" + cp_account_id + ":policy/" + policy_name 
        print("policy_arn=", policy_arn)
	ref = aws_sip.detach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)
        print("")
        print("going to delete role: role_name=", role_name)
        ref = aws_sip.role_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	# re-create the CPmemberXXX role 
        aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name, assume_role_policy_doc)

        ## attach policy to the CPmemberXXX role
        aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)

	return 

    def cp_user_remove(self, context, auth=None):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	cp_account_id = context['environment']['openstack.params']['auth']['CP_ACCOUNT_ID']
	user_name = context['environment']['openstack.params']['auth']['USER_NAME']

	### get info and verifications
	## get info from admin user
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
	admin_user_arn =  response['User']['Arn']
	admin_user_name =  response['User']['UserName']
	org_no = admin_user_arn.split(':')[4]

	## get the cp 
	try:
            cp = self.get_sip(cp_account_id)
        except exception.NotFound as e:
            raise exception.NotFound(e)
	if(cp['status'] == "0"):
	    print("The cp doesn't exist!")
	    return

	## verify the membership of org/admin in the sip (check if admin org is in the cp members)
	get_cp_members = cp['sip_members']
	# get admin org name 
	get_admin_org_name = ""
	for key, value in get_cp_members.iteritems():
	    if (value == org_no):
		get_admin_org_name = key
	org_name = get_admin_org_name
	if( org_name == ""):
	    print("Your org doesn't belong to the cp!")
	    return

        ## verify the normal user
	try:
            response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name)
        except exception.NotFound as e:
            raise exception.NotFound(e)

	### start removing the user
        ## get cp manager key
        manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
        manager_aws_access_secret_key = "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"

        ## assume cp manager role in the Sip
        cp_manager_role_arn = "arn:aws:iam::" + cp_account_id + ":role/SIDmanager"
        role_session_name = "cp_manager"
        assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
        response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, cp_manager_role_arn, role_session_name, assume_role_policy)

        ## get cp manager tempory key for assume role
        temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
        temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
        temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]

        ## verify the admin user in the cp
	# verify the admin user has a CPadminOrg role in the cp
	role_name = "CPadmin" + org_name
	response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	admin_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("admin_assume_role_policy_doc=", admin_assume_role_policy_doc)
        print("")
	# get admin role principlas (admin user arn) in the role
	admin_principals_aws = admin_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
	print("admin_principals_aws=", admin_principals_aws)
	if (admin_principals_aws != admin_user_arn):
	    print("The user is not an admin in the cp!")
	    raise exception.NotFound("The user is not an admin in the cp!")
	    return

	### SecAdmin user remove normal users from a Sip
        # Update CPmember roles (delete the role, then re-create it)
	role_name = "CPmember" + org_name
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
		print("User %s will be removed from the cp!", user_name)
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
        # delete the old CPmemberXXX role
	# get policy 
	policy_name = role_name
        print("")
        print("policy_name=", policy_name)
	# detach policy from the old role
	policy_arn = "arn:aws:iam::" + cp_account_id + ":policy/" + policy_name 
        print("policy_arn=", policy_arn)
	ref = aws_sip.detach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)
        print("")
        print("going to delete role: role_name=", role_name)
        ref = aws_sip.role_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
	# re-create the CPmemberXXX role 
        aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name, assume_role_policy_doc)

        ## attach policy to the CPmemberXXX role
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
	## generate a sid_id 
	random_string = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
	sid_id = random_string 

	## create core project
	core_project = self.core_project_create(sid_id, context)

	## create open project
	open_project = self.open_project_create(sid_id, context)

	## add a sid to SIDs table
	sid = {}
	sid['sid_id'] = sid_id 
	sid['sid_name'] = sid_name
	sid['sid_members'] = member_orgs
	sid['core_project'] = core_project
	sid['open_project'] = open_project
	sid = self.Mysid.add_sid(sid)	

	return sid

    def sid_delete(self, context, auth=None):
	member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	sid_id = context['environment']['openstack.params']['auth']['SID_ID']
	sid = self.get_sid(sid_id)
	cp_account_id = sid['core_project']
	op_account_id = sid['open_project']

	sips = self.Mysip.list_sips_by_sid(sid_id)
	print("")
	print("sips: ", sips)
	print("")
	for element in sips:
	    print("")
	    print("sip: ", element)
	    print("")
	    element_account_id = element['sip_account_id'] 
	    # delete core project
	    if(element_account_id == cp_account_id):
		core_project = self.core_project_delete(cp_account_id, member_orgs, context)
	    # delete open project
	    elif(element_account_id == op_account_id):
		open_project = self.open_project_delete(op_account_id, member_orgs, context)
	    # delete all the sips
	    else:
                sip = self._sip_delete(element_account_id, context)

	# delete sid record in db
	sid = self.Mysid.delete_sid(sid_id)
	return sid

    def core_project_create(self, sid_id, context):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	org_name = context['environment']['openstack.params']['auth']['AWS_ACCOUNT']
	member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	sid_name = context['environment']['openstack.params']['auth']['SID_NAME']
	    
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

	## pick up one available AWS account for the core_project
	cp_account_id = self.get_one_available_sip()
	cp = {}
	cp['status'] = "1"
	cp['sip_members'] = member_orgs
	cp['sip_account_id'] = cp_account_id
	cp['account_name'] = sid_name + "_cp"
	cp['sid_id'] = sid_id
	print("")	
	print("cp=", cp)	
	print("")	

	## create the core project (update the sip account)
	ref = self.update_sip(cp_account_id, cp)
	
	## get cp manager key
	manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
	manager_aws_access_secret_key = "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"

	## assume cp manager role in core project 
	cp_manager_role_arn = "arn:aws:iam::" + cp_account_id + ":role/SIDmanager"
	role_session_name = "cp_manager"
	assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
	response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, cp_manager_role_arn, role_session_name, assume_role_policy)
	print("")	
	print("Assume role credentials, response=", response)	
	print("")	

	## get cp manager tempory key for assume role
	temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
	temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
	temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]
	print("")	
	print("temp_manager_aws_access_key_id=", temp_manager_aws_access_key_id)	
	print("temp_manager_aws_access_secret_key=", temp_manager_aws_access_secret_key)	
	print("temp_manager_aws_access_session_token=", temp_manager_aws_access_session_token)	
	print("")	

	## create CPadmin/CPmember roles for organizations in the Sip
	## e.g. role name is like CPadminXXX/CPmemberXXX, XXX is org name
	path = "/"
	for org in member_orgs:
	    ## CPadminXXX roles:
	    role_name = "CPadmin" + org
	    assume_role_policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::" + member_orgs[org] + ":user/SecAdmin\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc = ", assume_role_policy_doc)
            role = aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name, assume_role_policy_doc)

	    ## create policies for CPadmin roles
	    policy_name = "CPadmin" + org
	    #policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Sid\": \"AllowSecAdminToListRolesUsers\", \"Effect\": \"Allow\", \"Action\": [ \"iam:ListRoles\", \"iam:ListUsers\", \"iam:ListPolicies\", \"iam:GetPolicy\" ], \"Resource\": [ \"arn:aws:iam::*\"  ] }, { \"Sid\": \"AllowSecAdminToUpdateAssumeRolePolicy\", \"Effect\": \"Allow\", \"Action\": [ \"iam:*\" ], \"Resource\": [ \"arn:aws:iam::" + cp_account_id + ":role/CPmember" + org + "\" ] } ] }"
	    policy_doc = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Sid\": \"AllowSecAdminToListRolesUsers\", \"Effect\": \"Allow\", \"Action\": [ \"iam:ListRoles\", \"iam:ListUsers\", \"iam:ListPolicies\", \"iam:GetPolicy\" ], \"Resource\": [ \"arn:aws:iam::*\"  ] } ] }"
	    role_policy = aws_sip.policy_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key,temp_manager_aws_access_session_token, policy_name, policy_doc)
	    print("CPadmin role policy:", role_policy)
	    ## attach policy to CPadmin roles
	    policy_arn = role_policy['Policy']['Arn']
            aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)

	    ## CPmemberXXX roles:
	    role_name2 = "CPmember" + org
	    assume_role_policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::" + member_orgs[org] + ":user/SecAdmin\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc2 = ", assume_role_policy_doc2)
            role2 = aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name2, assume_role_policy_doc2)

	    ## create policies for CPmember roles
	    policy_name2 = "CPmember" + org
	    policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\" } ] }"
	    role_policy2 = aws_sip.policy_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key,temp_manager_aws_access_session_token, policy_name2, policy_doc2)
	    print("CPmember role policy:", role_policy2)
	    ## attach policy to CPmember roles
	    policy_arn2 = role_policy2['Policy']['Arn']
            aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name2, policy_arn2)

        return cp_account_id

    def core_project_delete(self, cp_account_id, member_orgs, context):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']

        ## get info from admin user
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
        admin_user_arn =  response['User']['Arn']
        org_no = admin_user_arn.split(':')[4]
        print("")
        print("org_no = ", org_no)
        print("")

        ## get the cp
        try:
            cp = self.get_sip(cp_account_id)
        except exception.NotFound as e:
            raise exception.NotFound("Cannot find the core project!")
        if(cp['status'] == "0"):
            print("The core project doesn't exist!")
            return
        print("")
        print("cp=", cp)
        print("")
	sid_id = cp['sid_id']

        ## verify the membership of org/admin in the cp (check if admin org is in the cp members)
        get_sip_members = cp['sip_members']
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
            print("Your org doesn't belong to the core project!")
            return

        # verify the set of member organizations
        try:
            sid = self.get_sid(sid_id)
        except exception.NotFound as e:
            raise exception.NotFound("Can't find the sid!")
        members_in_sid = sid['sid_members']
        if( member_orgs != members_in_sid ):
            raise exception.NotFound("Sip member orgs dont match the sid members!")

	### delete roles and policies in the cp AWS account
        ## get cp manager key
        manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
        manager_aws_access_secret_key = "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"

        ## assume cp manager role in the Sip
        cp_manager_role_arn = "arn:aws:iam::" + cp_account_id + ":role/SIDmanager"
        role_session_name = "cp_manager"
        assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
        response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, cp_manager_role_arn, role_session_name, assume_role_policy)
        print("")
        print("Assume role credentials, response=", response)
        print("")

        ## get cp manager tempory key for assume role
        temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
        temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
        temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]
        print("")
        print("temp_manager_aws_access_key_id=", temp_manager_aws_access_key_id)
        print("temp_manager_aws_access_secret_key=", temp_manager_aws_access_secret_key)
        print("temp_manager_aws_access_session_token=", temp_manager_aws_access_session_token)
        print("")

        ## verify the admin user in the cp
        # verify the admin user has a CPadminOrg role in the cp
        role_name = "CPadmin" + org_name
        response = aws_sip.role_get(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)
        admin_assume_role_policy_doc = response['Role']['AssumeRolePolicyDocument']
        print("")
        print("admin_assume_role_policy_doc=", admin_assume_role_policy_doc)
        print("")
        # get admin role principlas (admin user arn) in the role
        admin_principals_aws = admin_assume_role_policy_doc['Statement'][0]['Principal']['AWS']
        print("admin_principals_aws=", admin_principals_aws)
        if (admin_principals_aws != admin_user_arn):
            print("The user is not an admin in the cp!")
            raise exception.NotFound("The user is not an admin in the cp!")
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
            if(role_name[0:2] == "CP"):
		# get policy 
		policy_name = role_name
	        # detach policies from the role
		policy_arn = "arn:aws:iam::" + cp_account_id + ":policy/" + policy_name 
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
	    if(policy_name[0:2] == "CP"):
                print("")
	        print("going to delete policy: policy_name=", policy_name)
		ref = aws_sip.policy_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, policy_arn)

        ## update the cp account to an available AWS account
	cp = {}
	cp['status'] = "0"
	cp['sip_members'] = {}
	cp['sip_account_id'] = cp_account_id
	cp['account_name'] = ""
	cp['sid_id'] = ""
	print("")	
	print("sip=", cp)	
	print("")	
        ref = self.update_sip(cp_account_id, cp)
	
	return ref

    def open_project_create(self, sid_id, context):
	aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
	aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']
	org_name = context['environment']['openstack.params']['auth']['AWS_ACCOUNT']
	member_orgs = context['environment']['openstack.params']['auth']['MEMBER_ORGS']
	sid_name = context['environment']['openstack.params']['auth']['SID_NAME']
	    
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
	    
	## get sec_admin org account number and sec_admin user name
	## e.g.: User ARN: arn:aws:iam::934324332443:user/SecAdmin
	sec_admin_name = response['User']['UserName']
	sec_admin_arn = response['User']['Arn']
	org_account_no = sec_admin_arn[13:24]

	## pick up one available AWS account for the open_project
	op_account_id = self.get_one_available_sip()
	op = {}
	op['status'] = "1"
	op['sip_members'] = member_orgs
	op['sip_account_id'] = op_account_id
	op['account_name'] = sid_name + "_op"
	op['sid_id'] = sid_id

	## create the open project (update the account)
	ref = self.update_sip(op_account_id, op)
	
	## get op manager key
	manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
	manager_aws_access_secret_key = "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"

	## assume op manager role in open project 
	op_manager_role_arn = "arn:aws:iam::" + op_account_id + ":role/SIDmanager"
	role_session_name = "op_manager"
	assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
	response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, op_manager_role_arn, role_session_name, assume_role_policy)

	## get op manager tempory key for assume role
	temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
	temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
	temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]

	## create OPmember role for organizations in open project
	## e.g. role name is like OPmemberXXX, XXX is org name
	path = "/"
	for org in member_orgs:
	    ## OPmemberXXX roles:
	    role_name2 = "OPmember" + org
	    assume_role_policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::" + member_orgs[org] + ":root\" }, \"Action\": \"sts:AssumeRole\" } ] }"
	    print("assume_role_policy_doc2 = ", assume_role_policy_doc2)
            role2 = aws_sip.role_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path, role_name2, assume_role_policy_doc2)

	    ## create policies for OPmember roles
	    policy_name2 = "OPmember" + org
	    policy_doc2 = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\" } ] }"
	    role_policy2 = aws_sip.policy_create(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key,temp_manager_aws_access_session_token, policy_name2, policy_doc2)
	    print("OPmember role policy:", role_policy2)
	    ## attach policy to OPmember roles
	    policy_arn2 = role_policy2['Policy']['Arn']
            aws_sip.attach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name2, policy_arn2)

        return op_account_id

    def open_project_delete(self, op_account_id, member_orgs, context):
        aws_access_key_id = context['environment']['openstack.params']['auth']['AWS_ACCESS_KEY_ID']
        aws_access_secret_key = context['environment']['openstack.params']['auth']['AWS_ACCESS_SECRET_KEY']

        ## get info from admin user
        response = aws_sip.user_get(aws_access_key_id, aws_access_secret_key, user_name=None)
        admin_user_arn =  response['User']['Arn']
        org_no = admin_user_arn.split(':')[4]

        ## get the op
        try:
            op = self.get_sip(op_account_id)
        except exception.NotFound as e:
            raise exception.NotFound("Cannot find the open project!")
        if(op['status'] == "0"):
            print("The open project doesn't exist!")
            return
	sid_id = op['sid_id']

        ## verify the membership of org/admin in the op (check if admin org is in the op members)
        get_sip_members = op['sip_members']
        # get admin org name
        get_admin_org_name = ""
        for key, value in get_sip_members.iteritems():
            if (value == org_no):
                get_admin_org_name = key
        org_name = get_admin_org_name
        if( org_name == ""):
            print("Your org doesn't belong to the open project!")
            return

        # verify the set of member organizations
        try:
            sid = self.get_sid(sid_id)
        except exception.NotFound as e:
            raise exception.NotFound("Can't find the sid!")
        members_in_sid = sid['sid_members']
        if( member_orgs != members_in_sid ):
            raise exception.NotFound("Sip member orgs dont match the sid members!")

	### delete roles and policies in the op AWS account
        ## get op manager key
        manager_aws_access_key_id = "AKIAJLXW5XRMHXXBRMLQ"
        manager_aws_access_secret_key = "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"

        ## assume op manager role in the Sip
        op_manager_role_arn = "arn:aws:iam::" + op_account_id + ":role/SIDmanager"
        role_session_name = "op_manager"
        assume_role_policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\" } ] }"
        response = aws_sip.assume_role(manager_aws_access_key_id, manager_aws_access_secret_key, op_manager_role_arn, role_session_name, assume_role_policy)

        ## get op manager tempory key for assume role
        temp_manager_aws_access_key_id = response["Credentials"]["AccessKeyId"]
        temp_manager_aws_access_secret_key = response["Credentials"]["SecretAccessKey"]
        temp_manager_aws_access_session_token = response["Credentials"]["SessionToken"]

        # list roles
        response = aws_sip.roles_list(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, path="/")
        index = 0
        for role in response["Roles"]:
            role_arn = response["Roles"][index]["Arn"]
            role_name = role_arn.split('/')[1]
            index = index + 1
	    
            # delete roles
            if(role_name[0:2] == "OP"):
		# get policy 
		policy_name = role_name
	        # detach policies from the role
		policy_arn = "arn:aws:iam::" + op_account_id + ":policy/" + policy_name 
		ref = aws_sip.detach_role_policy(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name, policy_arn)
                print("")
                print("going to delete role: role_name=", role_name)
                ref = aws_sip.role_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, role_name)

	# list policies
	response = aws_sip.policies_list(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, scope="Local", onlyattached=False, path="/")

	index = 0
	for policy in response["Policies"]:
	    policy_name = response["Policies"][index]["PolicyName"] 
	    policy_arn = response["Policies"][index]["Arn"]
	    index = index + 1
	    # delete policies
	    if(policy_name[0:2] == "OP"):
                print("")
	        print("going to delete policy: policy_name=", policy_name)
		ref = aws_sip.policy_delete(temp_manager_aws_access_key_id, temp_manager_aws_access_secret_key, temp_manager_aws_access_session_token, policy_arn)

        ## update the op account to an available AWS account
	op = {}
	op['status'] = "0"
	op['sip_members'] = {}
	op['sip_account_id'] = op_account_id
	op['account_name'] = ""
	op['sid_id'] = ""
        ref = self.update_sip(op_account_id, op)
	
	return ref


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
