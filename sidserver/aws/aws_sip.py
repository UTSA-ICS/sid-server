import boto3
import traceback

def aws_login(access_key_id, access_secret_key):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    print("")
    print("Listing boto3 roles")
    roles = client.list_roles()
    print("The roles are: ", roles)
    print("")
    return users

if __name__ == "__main__":
    aws_login()


def get_user(access_key_id, access_secret_key):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    user = client.get_user()
    print("")
    print("The user is: ", user)
    print("")
    return user

def policy_get(access_key_id, access_secret_key, policy_arn):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    #policy = client.get_policy(PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
    print("policy_arn=", policy_arn)
    policy = client.get_policy(PolicyArn=policy_arn)
    print("")
    print("The policy is: ", policy)
    print("")
    return policy

def policy_create(access_key_id, access_secret_key, policy_name, policy_doc):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    path='/' 
    desc=None
    policy = client.create_policy(PolicyName=policy_name, Path=path, PolicyDocument=policy_doc, Description=desc)
    #policy = client.create_policy(PolicyName='AssumeRoleTest', Path='/', PolicyDocument='', Description='')
    print("")
    print("The new created policy is: ", policy)
    print("")
    return policy

def policy_delete(access_key_id, access_secret_key, policy_arn):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    policy = client.delete_policy(PolicyArn=policy_arn)
    return policy

def role_get(access_key_id, access_secret_key, role_name):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    role = client.get_role(RoleName=role_name)
    return role

### create a role and the role's trust policy
def role_create(access_key_id, access_secret_key, path, role_name, assume_role_policy_doc):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    role = client.create_role(Path=path, RoleName=role_name, AssumeRolePolicyDocument=assume_role_policy_doc)
    print("")
    print("The new created role is: ", role)
    print("")
    return role

def role_delete(access_key_id, access_secret_key, role_name):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    role = client.delete_role(RoleName=role_name)
    return role

def attach_user_policy(access_key_id, access_secret_key, user_name, policy_arn):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    response = client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    print("")
    print("Policy is attached to a user!")
    print("")
    return response 

def detach_user_policy(access_key_id, access_secret_key, user_name, policy_arn):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    response = client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    return response 

### When you attach a managed policy to a role, the managed policy is used as the role's access (permissions) policy. You cannot use a managed policy as the role's trust policy. The role's trust policy is created at the same time as the role, using CreateRole . You can update a role's trust policy using UpdateAssumeRolePolicy . ###
def attach_role_policy(access_key_id, access_secret_key, role_name, policy_arn):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    response = client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    print("")
    print("Policy is attached to a role!")
    print("")
    return response 

def detach_role_policy(access_key_id, access_secret_key, role_name, policy_arn):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    response = client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    print("")
    print("Policy is attached to a role!")
    print("")
    return response 

def sip_create(access_key_id, access_secret_key):
    user = ""
    user = get_user(access_key_id, access_secret_key)
    if (user == ""):
	print("The user doesn't exist!")
	return
    ## get sip account and sip manager admin's access key and secret key
    #sip_account_no="652714115935"
    #sip_access_key_id="AKIAIWPSDHPRDSGFEGMQ"
    #sip_access_secret_key= "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"
    #admin_role = ""
    #admin_role = create_role(sip_access_key_id, sip_access_secret_key, "SIPadmin")
    #member_role = create_role(sip_access_key_id, sip_access_secret_key, "SIPmember")
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    policy = ""
    policy = get_policy(access_key_id, access_secret_key, policy_arn)
    assume_role_policy = ""
    policy_document = """{
	  "Version": "2012-10-17",
	  "Statement": [
	    {
	      "Effect": "Allow",
	      "Principal": {
  	      "AWS": [
	          "arn:aws:iam::934324332443:root",
	          "arn:aws:iam::042298307144:root"
	        ]
	      },
	      "Action": "sts:AssumeRole"
	    }
	  ]
	}
	"""
    #assume_role_policy = create_policy(sip_access_key_id, sip_access_secret_key,"AssumeRole", policy_document)

    return user






