#!/bin/bash
cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}
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

describe_cluster

exit 0
