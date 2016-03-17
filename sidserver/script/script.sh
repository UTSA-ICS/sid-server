
curl -i 'http://10.245.121.24:5000/v2.0/aws/user_get' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/user_create' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_USER_NAME":"SecAdmin"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/policy_get' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_POLICY_ARN":"arn:aws:iam::934324332443:policy/AssumeRole"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/policies_list' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/policy_delete' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_POLICY_ARN":"arn:aws:iam::934324332443:policy/AssumeRoleTest"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/policy_create' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_POLICY_NAME":"AssumeRoleTest"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/roles_list' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/role_get' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_ROLE_NAME":"CPSDummyRole"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/role_create' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_ROLE_NAME":"SIPadminTest"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/role_delete' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_ROLE_NAME":"SIPadminTest"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/attach_user_policy' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_USER_NAME":"SecAdmin", "AWS_POLICY_ARN":"arn:aws:iam::934324332443:policy/AssumeRole"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/attach_user_policy' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_USER_NAME":"SecAdmin", "AWS_POLICY_ARN":"arn:aws:iam::aws:policy/AdministratorAccess"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/detach_user_policy' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_USER_NAME":"SecAdmin", "AWS_POLICY_ARN":"arn:aws:iam::934324332443:policy/AssumeRole"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/user_delete' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_USER_NAME":"SecAdmin"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/attach_role_policy' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_ROLE_NAME":"CPSDummyRole", "AWS_POLICY_ARN":"arn:aws:iam::aws:policy/AmazonEC2FullAccess"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/detach_role_policy' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "AWS_ROLE_NAME":"CPSDummyRole", "AWS_POLICY_ARN":"arn:aws:iam::aws:policy/AmazonEC2FullAccess"}}'

curl -i 'http://10.245.121.24:5000/v2.0/aws/sip_create' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":"AKIAIPNDBPV3TDEHSLFQ", "AWS_ACCESS_SECRET_KEY":"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", "AWS_ACCOUNT":"CPS", "MEMBER_ORGS":["042298307144", "934324332443"], "SecAdmin_USERS":["SecAdminCPS", "SecAdminSAWS"]}}'



