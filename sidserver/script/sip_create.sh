#!/bin/bash

AWS_ACCESS_KEY_ID=$1
AWS_ACCESS_SECRET_KEY=$2
AWS_ACCOUNT=CPS

# notes: use double quote instead of single quote!!
data="{\"auth\":{\"AWS_ACCESS_KEY_ID\":\"$AWS_ACCESS_KEY_ID\",\"AWS_ACCESS_SECRET_KEY\":\"$AWS_ACCESS_SECRET_KEY\",\"AWS_ACCOUNT\":\"$AWS_ACCOUNT\"}}"
echo data=$data

curl -i 'http://10.245.121.24:5000/v2.0/tokens/create_sip' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d "$data"
 
# notes: sample curl cmd
#curl -i 'http://10.245.121.24:5000/v2.0/tokens/create_sip' -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d '{"auth":{"AWS_ACCESS_KEY_ID":"AKIAJK2AALLFSJDCUTOQ","AWS_ACCESS_SECRET_KEY":"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","AWS_ACCOUNT":"CPS"}}'
