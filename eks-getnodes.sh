#!/bin/bash

cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}

list_nodes() {
  NODES=$(kubectl get nodes -o jsonpath='{.items..metadata.name}')
  for node in ${NODES} ; do
    echo -n "${node} / "
    aws --region ${region} ec2 describe-instances --output json --query "Reservations[?Instances[?PrivateDnsName==\`${node}\`]]" | jq -r '.[].Instances[0].PublicDnsName'
  done
}

list_nodes
