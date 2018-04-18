#!/bin/bash

cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}

delete_cluster (){
  if [ "${KUBECTL_PLUGINS_LOCAL_FLAG_IM_INSANE}" == "ForSure" ] ; then
    echo aws --region ${region} eks delete-cluster --cluster-name ${cluster} 
  else
    echo "Are you sure you want to delete the cluster?"
    echo "if so, specify the --im-insane=ForSure parameter to this command"
    exit 0
  fi
}

delete_cluster
