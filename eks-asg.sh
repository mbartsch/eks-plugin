#!/bin/bash -x



autoscaling () {
  region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}
  cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
  region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}
  ASGS=$(aws --output text --region ${region} autoscaling \
    describe-auto-scaling-groups \
    --query "AutoScalingGroups[?Tags[?Key==\`kubernetes.io/cluster/${cluster}\`]] | [].AutoScalingGroupName")
  if [ $(echo ${ASGS} | IFS=' ' wc -w) -gt 1 ] && [ -z "${KUBECTL_PLUGINS_LOCAL_FLAG_ASG_NAME}" ] ; then
    echo "Mode than 1 ASG found"
    echo "Available AutoScaling Groups:"
    for asg in ${ASGS}; do 
      echo -e "\t${asg}"
    done
    exit 1
  fi
  #ASG=${ASGS:-$KUBECTL_PLUGINS_LOCAL_FLAG_ASG_NAME}
  ASG=${KUBECTL_PLUGINS_LOCAL_FLAG_ASG_NAME:-${ASGS}}
  echo "Using ASG: ${ASG}"
  if [ ! -z "${KUBECTL_PLUGINS_LOCAL_FLAG_MAX}" ]; then
    MAXSIZE="--max-size ${KUBECTL_PLUGINS_LOCAL_FLAG_MAX}"
  fi
  if [ ! -z "${KUBECTL_PLUGINS_LOCAL_FLAG_MIN}" ]; then
    MINSIZE="--min-size ${KUBECTL_PLUGINS_LOCAL_FLAG_MIN}"
  fi
  if [ ! -z "${KUBECTL_PLUGINS_LOCAL_FLAG_DESIRED}" ]; then
    SIZE="--desired-capacity ${KUBECTL_PLUGINS_LOCAL_FLAG_DESIRED}"
  fi
  
  aws --region ${region} autoscaling update-auto-scaling-group \
    --auto-scaling-group-name ${ASG} ${SIZE} ${MAXSIZE} ${MINSIZE}
  exit $?  
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

autoscaling

exit 0
