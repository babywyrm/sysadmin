#!/bin/bash

##
##

USA_ACCOUNTS=("something" "something-else "somewhere" "bye")

echo "Clean it..."
sleep 1
rm output/*

printf '%s\n' "${USA_ACCOUNTS[@]}"
sleep 2

for TENANT in "${USA_ACCOUNTS[@]}"
##for TENANT in groupone grouptwo groupthree 
do
	for region in us-east-1 us-east-2 us-west-1 us-west-2
	do	
		echo "Crunching $TENANT all regions.." ; saml2aws -a identity-readonly exec -- aws --profile $TENANT --region $region ec2 describe-instances | jq -r '.Reservations[]|.Instances[]|[(.Tags[]?|select(.Key=="Name")|.Value), (.Tags[]?|select(.Key=="Group-Name")|.Value),.InstanceId,.State.code,.State.Name,.PrivateIpAddress]|@csv'|sort | grep running >> output/$TENANT.log
	done
	sleep 1 ; echo "Next one.."
done

echo "All done for the united states prod.."
echo "Now let's do Europe I guess.."
echo "Lmao......"

sleep 1

#################

EU_ACCOUNTS=("eu1-prod-ro" "eu1-dr-prod-ro")




#################
##
##

#
# Different region!
# for acct_num in "${MEDAL_ACCOUNTS[@]}"
# do
#  echo "Starting $acct_num..."
#  saml2aws exec -a $acct_num 'aws-list-all query --region us-west-2 | grep "+++" | cut -d" " -f2 | sort | uniq' > $acct_num.txt
#  echo "Cleaning json files..."
#  rm -f *.json
# done

##
##
##
##22316  saml2aws -a identity-readonly exec -- aws --profile things-ro --region us-east-1 ec2 describe-instances | jq -r '.Reservations[]|.Instances[]|[(.Tags[]?|select(.Key=="Name")|.Value), (.Tags[]?|select(.Key=="Group-Name")|.Value),.InstanceId,.State.code,.State.Name,.PrivateIpAddress]|@csv'|sort | grep running | wc -l
##22317  saml2aws -a identity-readonly exec -- aws --profile things-tho-ro --region us-east-1 ec2 describe-instances | jq -r '.Reservations[]|.Instances[]|[(.Tags[]?|select(.Key=="Name")|.Value), (.Tags[]?|select(.Key=="Group-Name")|.Value),.InstanceId,.State.code,.State.Name,.PrivateIpAddress]|@csv'|sort | grep running
