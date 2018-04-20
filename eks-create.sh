#!/bin/bash

cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}

create_cluster() {
  if [ -z "${KUBECTL_PLUGINS_LOCAL_FLAG_SUBNET_IDS}" ] ; then
    SUBNETS=$(aws ec2 describe-subnets --region ${region} --filter Name=tag-key,Values="kubernetes.io/cluster/${cluster}" --query 'Subnets[].SubnetId' --output text)
  else 
    SUBNETS=${KUBECTL_PLUGINS_LOCAL_FLAG_SUBNET_IDS}
  fi 
  if [ -z "${KUBECTL_PLUGINS_LOCAL_FLAG_SECURITY_GROUP_IDS}" ] ; then
    SECGROUPS=$(aws ec2 describe-security-groups --region ${region} --filter Name=tag-key,Values="kubernetes.io/cluster/${cluster}" --query 'SecurityGroups[].GroupId' --output text)
  else
    SECGROUPS=${KUBECTL_PLUGINS_LOCAL_FLAG_SECURITY_GROUP_IDS}
  fi
  #SECGROUPS=$(echo ${SECGROUPS} | sed -e 's/ /,/g')
  if [ -z "${KUBECTL_PLUGINS_LOCAL_FLAG_SERVICE_ROLE_ARN}" ] ; then
    ARN=$(aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==`eks.amazonaws.com`]]| [0]| Arn' | sed -e 's/"//g')
  else
    ARN=${KUBECTL_PLUGINS_LOCAL_FLAG_SERVICE_ROLE_ARN}
  fi
  echo ${SUBNETS}
  echo ${SECGROUPS}
  echo "This will create the cluster ${cluster} on the region ${region} using the follwing"
  echo "Subnets:"
  echo -e "\t${SUBNETS}"
  echo "Security Groups"
  echo -e "\t${SECGROUPS}"
  echo "Service Role Arn"
  echo -e "\t${ARN}"
  aws eks --region ${region} create-cluster --cluster-name ${cluster} --security-groups ${SECGROUPS} --subnets ${SUBNETS} --role-arn ${ARN} --output text --query 'cluster.[clusterName,status]'
  exit 0
}

create_cluster
