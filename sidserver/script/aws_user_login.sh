#!/bin/bash

AWS_ACCESS_KEY_ID=$1
AWS_ACCESS_SECRET_KEY=$2
AWS_ACCOUNT=CPS

curl -i 'http://10.245.121.24:5000/v2.0/tokens/aws/user_login' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth": {"AWS_ACCESS_KEY_ID":\"$AWS_ACCESS_KEY_ID\", "AWS_ACCESS_SECRET_KEY":\"$AWS_ACCESS_SECRET_KEY\", "AWS_ACCOUNT":"CPS"}}'
