from azure.graphrbac.models import UserCreateParameters, UserCreateParametersPasswordProfile

def azure_login():
    print("")
    print("Check permissions for a resource group!")
    group_name = 'Sip2gp1'
    permissions = authorization_client.permissions.list_for_resource_group(group_name)
    print("The permissions are: ", permissions)
    print("")
    return permissions

#if __name__ == "__main__":
#    azure_login()

def user_list(client):
    user_list = client.user.list()
    user_list.reset()
    items = user_list.next()
    for i in items:
	print("user:", i.display_name)
    return user_list

def user_create(client, parameters):
    user = client.user.create(
        UserCreateParameters(
            account_enabled=False,
            display_name=parameters['DISPLAY_NAME'],
            mail_nickname=parameters['MAIL_NICKNAME'],
            password_profile=UserCreateParametersPasswordProfile(
                password="MyStr0ngP4ssword",
                force_change_password_next_login=True
            ),
            user_principal_name=parameters['USER_PRINCIPAL_NAME']
        )
    )
    # user is a User instance
    #self.assertEqual(user.display_name, 'Test Buddy')
    #user = graphrbac_client.user.get(user.object_id)
    #self.assertEqual(user.display_name, 'Test Buddy')
    #for user in graphrbac_client.user.list(filter="displayName eq 'Test Buddy'"):
    #    self.assertEqual(user.display_name, 'Test Buddy')
    #graphrbac_client.user.delete(user.object_id)

    return user

def user_get(client, user_id):
    #user_id = "testbuddy@SIDdomain.onmicrosoft.com"
    user = client.user.get(user_id )
    print("user:", user.display_name)
    return user

def user_delete(client, user_id):
    #user_id = "testbuddy@SIDdomain.onmicrosoft.com"
    user = client.user.delete(user_id)
    return user

def policies_list(access_key_id, access_secret_key, scope, onlyattached, path):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    #role = client.list_policies(Scope=scope, OnlyAttached=onlyattached, PathPrefix=path, Marker=marker, MaxItems=123)
    role = client.list_policies(Scope=scope, OnlyAttached=onlyattached, PathPrefix=path, MaxItems=123)
    return role

def policy_get(access_key_id, access_secret_key, policy_arn):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    #policy = client.get_policy(PolicyArn='arn:azure:iam::azure:policy/AdministratorAccess')
    print("policy_arn=", policy_arn)
    policy = client.get_policy(PolicyArn=policy_arn)
    print("")
    print("The policy is: ", policy)
    print("")
    return policy

def policy_create(access_key_id, access_secret_key, policy_name, policy_doc):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    path='/' 
    desc=''
    policy = client.create_policy(PolicyName=policy_name, Path=path, PolicyDocument=policy_doc, Description=desc)
    #policy = client.create_policy(PolicyName='AssumeRoleTest', Path='/', PolicyDocument='', Description='')
    print("")
    print("The new created policy is: ", policy)
    print("")
    return policy

def policy_delete(access_key_id, access_secret_key, policy_arn):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    policy = client.delete_policy(PolicyArn=policy_arn)
    return policy

def roles_list(access_key_id, access_secret_key, path):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    #role = client.list_roles(PathPrefix=path, Marker=marker, MaxItems=123)
    role = client.list_roles(PathPrefix=path, MaxItems=123)
    return role

def role_get(access_key_id, access_secret_key, role_name):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    role = client.get_role(RoleName=role_name)
    return role

### create a role and the role's trust policy
def role_create(access_key_id, access_secret_key, path, role_name, assume_role_policy_doc):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    role = client.create_role(Path=path, RoleName=role_name, AssumeRolePolicyDocument=assume_role_policy_doc)
    print("")
    print("The new created role is: ", role)
    print("")
    return role

def role_delete(access_key_id, access_secret_key, role_name):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    role = client.delete_role(RoleName=role_name)
    return role

def attach_user_policy(access_key_id, access_secret_key, user_name, policy_arn):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    response = client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    print("")
    print("Policy is attached to a user!")
    print("")
    return response 

def detach_user_policy(access_key_id, access_secret_key, user_name, policy_arn):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    response = client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    return response 

### When you attach a managed policy to a role, the managed policy is used as the role's access (permissions) policy. You cannot use a managed policy as the role's trust policy. The role's trust policy is created at the same time as the role, using CreateRole . You can update a role's trust policy using UpdateAssumeRolePolicy . ###
def attach_role_policy(access_key_id, access_secret_key, role_name, policy_arn):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    response = client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    print("")
    print("Policy is attached to a role!")
    print("")
    return response 

def detach_role_policy(access_key_id, access_secret_key, role_name, policy_arn):
    client = boto3.client('iam', azure_access_key_id=access_key_id, azure_secret_access_key=access_secret_key)
    response = client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    print("")
    print("Policy is detached from a role!")
    print("")
    return response 



