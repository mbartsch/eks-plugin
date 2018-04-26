#!/bin/bash

if [ -z ${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME} ] && [ "${KUBECTL_PLUGINS_LOCAL_FLAG_ACTION}" != "list" ]; then
  echo "Cluster name must be specified"
  exit 1
fi

cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}

list_cluster() {
  aws --region us-west-2 eks list-clusters --output text
}

describe_cluster(){
  JSON=$(aws --region ${region} eks describe-cluster --cluster-name ${cluster} --output json)
  status=$(echo ${JSON} | jq -r '.cluster.status')
  clusterName=$(echo ${JSON} | jq -r '.cluster.clusterName')
  desiredMasterVersion=$(echo ${JSON} | jq -r '.cluster.desiredMasterVersion')
  masterEndpoint=$(echo ${JSON} | jq -r '.cluster.masterEndpoint')
  roleArn=$(echo ${JSON} | jq -r '.cluster.roleArn')
  roleArn=$(echo ${JSON} | jq -r '.cluster.roleArn')
  subnets="$(echo ${JSON} | jq -r '.cluster.subnets | @csv ' | sed -e 's/\"//g')"
  securityGroups="$(echo ${JSON} | jq -r '.cluster.securityGroups | @csv ' | sed -e 's/\"//g')"
  echo -e "Cluster Name    : ${clusterName}"
  echo -e "Cluster status  : ${status}"
  echo -e "Master Version  : ${desiredMasterVersion}"
  echo -e "End Point       : ${masterEndpoint}"
  if [ "${KUBECTL_PLUGINS_LOCAL_FLAG_DETAIL}" != "no" ] ; then
    echo -e "Subnets         : ${subnets}"
    echo -e "Security Groups : ${securityGroups}"
    echo -e "role Arn        : ${roleArn}"
    if [ "${KUBECTL_PLUGINS_LOCAL_FLAG_DETAIL}" == "cert" ] ; then
      echo -e "Certificate Data: $(echo ${JSON} | jq -r '.cluster.certificateAuthority.data')"
    fi
  fi

}
delete_cluster (){
  echo aws --region ${region} eks delete-cluster --cluster-name ${cluster} 
}

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
  aws eks --region ${region} create-cluster --cluster-name ${cluster} --security-groups ${SECGROUPS} --subnets ${SUBNETS} --role-arn ${ARN} --output text
  exit 0
}

case ${KUBECTL_PLUGINS_LOCAL_FLAG_ACTION} in
  list)
    list_cluster
    ;;
  describe)
    describe_cluster
    ;;
  create)
    create_cluster
    ;;
  delete)
    delete_cluster
    ;;
  *)
    export
    echo "Bad Parameters"
    exit 2
    ;;
esac
exit




exit 0
