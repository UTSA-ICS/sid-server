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
  echo "   Sample AWS Credentials:"
  echo "   	AWS_ACCESS_KEY_ID=AKIAIPNDBPV3TDEHSLFQ"
  echo "	AWS_ACCESS_SECRET_KEY=7XimtnZ0iAfaKnZwBjTIf/uGqqFnKPC9+HEvB8iq"
  echo "	AWS_ACCOUNT=CPS"
  echo ""
  exit 1
fi

if [ -z $AWS_ACCOUNT ];then 
	AWS_ACCOUNT=$2
	if [ -z $AWS_ACCESS_KEY_ID ];then AWS_ACCESS_KEY_ID=$3;fi
	if [ -z $AWS_ACCESS_SECRET_KEY ];then AWS_ACCESS_SECRET_KEY=$4;fi
else
	if [ -z $AWS_ACCESS_KEY_ID ];then AWS_ACCESS_KEY_ID=$2;fi
	if [ -z $AWS_ACCESS_SECRET_KEY ];then AWS_ACCESS_SECRET_KEY=$3;fi
fi

AUTH_CREDENTIALS="{ \"auth\": { \"AWS_ACCESS_KEY_ID\":\"$AWS_ACCESS_KEY_ID\", \"AWS_ACCESS_SECRET_KEY\":\"$AWS_ACCESS_SECRET_KEY\", \"AWS_ACCOUNT\":\"$AWS_ACCOUNT\" } }"
MATCH_PATTERN="grep \"{.*}\""

if [ -z $OS_AUTH_URL ];then 
	echo ""
	echo "NO Auth URL Set, Please run <source openrc admin admin>"
	echo "Exiting...."
	echo ""
	exit 1
else
	SID_URL=`echo $OS_AUTH_URL |sed s/:50.*//`":5123/v2.0"
fi

echo ""
CURL_CMD=`curl -s -i $SID_URL/aws/$SID_CMD -X POST  -H "Content-Type: application/json" -H "Accept: application/json" -d "$AUTH_CREDENTIALS"`
# For Debugging
#echo $CURL_CMD
echo $CURL_CMD | grep {.*}
echo ""

