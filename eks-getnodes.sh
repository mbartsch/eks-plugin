#!/bin/bash

cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}
node=${KUBECTL_PLUGINS_LOCAL_FLAG_NODE}

list_nodes() {
  NODES=$(kubectl get nodes -o jsonpath='{.items..metadata.name}')
  if [ ! -z ${node} ] ;then 
    aws --region ${region} ec2 describe-instances --output json --query "Reservations[?Instances[?PrivateDnsName==\`${node}\`]]" | jq -r '.[].Instances[0].PublicDnsName'
  else 
    for node in ${NODES} ; do
      echo -n "${node} / "
      aws --region ${region} ec2 describe-instances --output json --query "Reservations[?Instances[?PrivateDnsName==\`${node}\`]]" | jq -r '.[].Instances[0].PublicDnsName'
    done
  fi
}

list_nodes $node
