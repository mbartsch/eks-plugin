#!/bin/bash

cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}

list_cluster() {
  aws --region ${region} eks list-clusters --output text
}

list_cluster
