#import boto.sts
#import boto.iam
#import exceptions
#from boto.ec2.connection import EC2Connection
import boto3


def aws_login(access_key_id, access_secret_key):
    #regions = boto.iam.regions()
    #iamconn = boto.iam.connection.IAMConnection(aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    print("STARTING to try boto3")
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    print("")
    print("Listing boto3 roles")
    roles = client.list_roles()
    print("The roles are: ", roles)
    #for r in roles.list_roles_response.list_roles_result.roles:
    #    print("The roles are: ", r.role_name)
    users = client.get_user()
    print("The user is :", client.get_user())
    print("")
    #for user in users.list_users_response.list_users_result.users:
    #    print("The users are: ", user.user_name)

    return users

if __name__ == "__main__":
    aws_login()


def get_user(access_key_id, access_secret_key):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    user = client.get_user()
    print("")
    print("The user is: ", user)
    #print("The name of the user is: ", user.user_name)
    print("")
    return user

def get_policy(access_key_id, access_secret_key, policy_arn):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    #policy = client.get_policy(policy_arn)
    policy = client.get_policy(PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
    print("")
    print("The policy is: ", policy)
    #print("The name of the policy is: ", policy.policy_name)
    print("")
    return roles

def create_role(access_key_id, access_secret_key, RoleName, AssumeRolePolicyDocument):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    Path = None
    role = client.create_role(Path, RoleName, AssumeRolePolicyDocument)
    #role = client.create_role(role_name, assume_role_policy_document=None, path=None)
    print("")
    print("The new created role is: ", role)
    #print("The role's name is: ", role.role_name)
    print("")
    return role

def create_policy(access_key_id, access_secret_key, PolicyName, PolicyDocument):
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_secret_key)
    #policy = client.create_policy(policy_name, policy_document, path='/', description=None)
    Path = '/'
    Description=None
    policy = client.create_policy(PolicyName, Path, PolicyDocument, Description)
    print("")
    print("The new created policy is: ", policy)
    #print("The policy's name is: ", policy.policy_name)
    print("")
    return policy

def sip_create(access_key_id, access_secret_key):
    user = ""
    user = get_user(access_key_id, access_secret_key)
    if (user == ""):
	print("The user doesn't exist!")
	return
    ## get sip account and sip manager admin's access key and secret key
    sip_account_no="652714115935"
    sip_access_key_id="AKIAIWPSDHPRDSGFEGMQ"
    sip_access_secret_key= "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"
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






