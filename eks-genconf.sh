#!/bin/bash
cluster=${KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME}
region=${KUBECTL_PLUGINS_LOCAL_FLAG_REGION}
showconfig(){
  JSON=$(aws --region ${region} eks describe-cluster --cluster-name ${cluster} --output json 2>/dev/null)
  status=$(echo ${JSON} | jq -r '.cluster.status')
  clusterName=$(echo ${JSON} | jq -r '.cluster.clusterName')
  masterEndpoint=$(echo ${JSON} | jq -r '.cluster.masterEndpoint')
  if [ "${status}" != "ACTIVE" ] ; then
    echo "The cluster ${cluster} is not ACTIVE, can't generate configuration"
    echo "if you just create this, please allow 5 to 10 minutes and try again"
    exit 1
  fi 
  mkdir -p ~/.kube/config.d
  cat<<EOF>~/.kube/config.d/${clusterName}.yaml
apiVersion: v1
clusters:
  - cluster:
      certificate-authority-data: >-
        $(echo ${JSON} | jq -r '.cluster.certificateAuthority.data')
      server: ${masterEndpoint}
    name: kubernetes-${clusterName}
contexts:
  - context:
      cluster: kubernetes-${clusterName}
      user: kubernetes-admin-${clusterName}
    name: aws-${clusterName}
current-context: aws
kind: Config
preferences: {}
users:
  - name: kubernetes-admin-${clusterName}
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1alpha1
        command: heptio-authenticator-aws
        args:
          - token
          - '-i'
          - ${clusterName}
EOF
echo "Now you need to add ~/.kube/config.d/${clusterName}.yaml to your"
echo "\$KUBECONFIG environment variable"
echo "export KUBECONFIG=$KUBECONFIG:~/.kube/config.d/${clusterName}.yaml"
}

showconfig

exit 0
