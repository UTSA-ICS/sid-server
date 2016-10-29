import boto3
import traceback

def __init__(self):
    self.sts_client = boto3.client('sts', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    self.iam_client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)

def openstack_login(access_key_id, access_secret_key):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    print("")
    print("Listing boto3 roles")
    roles = client.list_roles()
    print("The roles are: ", roles)
    print("")
    return users

#if __name__ == "__main__":
#    openstack_login()


def user_get(access_key_id, access_secret_key, user_name):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    if (user_name == None):
	user = client.get_user()
    else:
        user = client.get_user(UserName=user_name)
    #print("")
    #print("The user is: ", user)
    #print("")
    return user

def user_create(access_key_id, access_secret_key, path, user_name):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    user = client.create_user(Path=path, UserName=user_name)
    #print("")
    #print("The new created user is: ", user)
    #print("")
    return user

def user_delete(access_key_id, access_secret_key, user_name):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    user = client.delete_user(UserName=user_name)
    return user

def policies_list(access_key_id, access_secret_key, session_token, scope, onlyattached, path):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    #policy = client.list_policies(Scope=scope, OnlyAttached=onlyattached, PathPrefix=path, Marker=marker, MaxItems=123)
    policy = client.list_policies(Scope=scope, OnlyAttached=onlyattached, PathPrefix=path, MaxItems=123)
    return policy

def policy_get(access_key_id, access_secret_key, session_token, policy_arn):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    #policy = client.get_policy(PolicyArn='arn:openstack:iam::openstack:policy/AdministratorAccess')
    #print("policy_arn=", policy_arn)
    policy = client.get_policy(PolicyArn=policy_arn)
    #print("")
    #print("The policy is: ", policy)
    #print("")
    return policy

def policy_create(access_key_id, access_secret_key, session_token, policy_name, policy_doc):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    path='/' 
    desc=''
    policy = client.create_policy(PolicyName=policy_name, Path=path, PolicyDocument=policy_doc, Description=desc)
    #policy = client.create_policy(PolicyName='AssumeRoleTest', Path='/', PolicyDocument='', Description='')
    #print("")
    #print("The new created policy is: ", policy)
    #print("")
    return policy

def policy_delete(access_key_id, access_secret_key, session_token, policy_arn):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    policy = client.delete_policy(PolicyArn=policy_arn)
    return policy

def role_policy_get(access_key_id, access_secret_key, session_token, role_name, policy_name):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    role = client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    return role

def roles_list(access_key_id, access_secret_key, session_token, path):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    #role = client.list_roles(PathPrefix=path, Marker=marker, MaxItems=123)
    role = client.list_roles(PathPrefix=path, MaxItems=123)
    return role

def role_get(access_key_id, access_secret_key, session_token, role_name):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    role = client.get_role(RoleName=role_name)
    return role

### create a role and the role's trust policy
def role_create(access_key_id, access_secret_key, session_token, path, role_name, assume_role_policy_doc):
    #client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    role = client.create_role(Path=path, RoleName=role_name, AssumeRolePolicyDocument=assume_role_policy_doc)
    print("")
    print("The new created role is: ", role)
    print("")
    return role

def role_delete(access_key_id, access_secret_key, session_token, role_name):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    role = client.delete_role(RoleName=role_name)
    return role

def attach_user_policy(access_key_id, access_secret_key, user_name, policy_arn):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    response = client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    print("")
    print("Policy is attached to a user!")
    print("")
    return response 

def detach_user_policy(access_key_id, access_secret_key, user_name, policy_arn):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    response = client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    return response 

### When you attach a managed policy to a role, the managed policy is used as the role's access (permissions) policy. You cannot use a managed policy as the role's trust policy. The role's trust policy is created at the same time as the role, using CreateRole . You can update a role's trust policy using UpdateAssumeRolePolicy . ###
def attach_role_policy(access_key_id, access_secret_key, session_token, role_name, policy_arn):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    response = client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    print("")
    print("Policy is attached to a role!")
    print("")
    return response 

def detach_role_policy(access_key_id, access_secret_key, session_token, role_name, policy_arn):
    client = boto3.client('iam', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key, openstack_session_token=session_token)
    response = client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    print("")
    print("Policy is detached from a role!")
    print("")
    return response 

#def assume_role(access_key_id, access_secret_key, role_arn, role_session_name, policy, external_id, serial_number, token_code):
def assume_role(access_key_id, access_secret_key, role_arn, role_session_name, assume_role_policy):
    client = boto3.client('sts', openstack_access_key_id=access_key_id, openstack_secret_access_key=access_secret_key)
    #response = client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name, DurationSeconds=3600, ExternalId=external_id, SerialNumber=None, TokenCode=None)
    response = client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name, Policy=assume_role_policy, DurationSeconds=3600)
    print("")
    print("Role is assumed!")
    print("")
    return response 


