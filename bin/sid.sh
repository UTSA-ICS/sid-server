#!/bin/bash

SID_CMD=$1
if [ -z $SID_CMD ];then
  echo ""
  echo "#################################"
  echo " Error: No parameters specified!"
  echo "#################################"
  echo ""
  echo " Usage: $0 {<SID Command> <AWS_ACCOUNT> <AWS_ACCESS_KEY_ID> <AWS_ACCESS_SECRET_KEY>}"
  echo ""
  echo " Optionally the following variables can also be set:"
  echo "   export AWS_ACCOUNT=<AWS Account name>"
  echo "   export AWS_ACCESS_KEY_ID=<AWS Access Key ID>"
  echo "   export AWS_ACCESS_SECRET_KEY=<AWS Access Secret Key>"
  echo ""
  exit 1
fi

if [ -z AWS_ACCOUNT ];then AWS_ACCOUNT=$2;fi
if [ -z AWS_ACCESS_KEY_ID ];then AWS_ACCESS_KEY_ID=$3;fi
if [ -z AWS_ACCESS_SECRET_KEY ];then AWS_ACCESS_SECRET_KEY=$4;fi

AUTH_CREDENTIALS="{ \"auth\": { \"AWS_ACCESS_KEY_ID\":\"$AWS_ACCESS_KEY_ID\", \"AWS_ACCESS_SECRET_KEY\":\"$AWS_ACCESS_SECRET_KEY\", \"AWS_ACCOUNT\":\"$AWS_ACCOUNT\" } }"
MATCH_PATTERN="grep {.*}"

echo ""
curl -s -i http://10.245.121.24:5000/v2.0/aws/$SID_CMD -X POST  -H "Content-Type: application/json" -H "Accept: application/json" -d "$AUTH_CREDENTIALS" | $MATCH_PATTERN
echo ""


#AWS_ACCESS_KEY_ID="AKIAIPNDBPV3TDEHSLFQ"
#AWS_ACCESS_SECRET_KEY="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"
#AWS_ACCOUNT="CPS"
