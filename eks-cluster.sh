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
  aws --region ${region} eks describe-cluster --cluster-name ${cluster} --output json
}
delete_cluster (){
  echo aws --region ${region} eks delete-cluster --cluster-name ${cluster} 
}

create_cluster() {
  SUBNETS=$(aws ec2 describe-subnets --region ${region} --filter Name=tag-key,Values="kubernetes.io/cluster/${cluster}" --query 'Subnets[].SubnetId' --output text)
  #SUBNETS=$(echo ${SUBNETS} | sed -e 's/ /,/g')
  SECGROUPS=$(aws ec2 describe-security-groups --region ${region} --filter Name=tag-key,Values="kubernetes.io/cluster/${cluster}" --query 'SecurityGroups[].GroupId' --output text)
  #SECGROUPS=$(echo ${SECGROUPS} | sed -e 's/ /,/g')
  ARN=$(aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==`eks.amazonaws.com`]]| [0]| Arn' | sed -e 's/"//g')
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
    echo "Bad Parameters"
    exit 2
esac
exit




exit 0
