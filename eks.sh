#!/bin/bash

help() {
cat<<EOF
  This plugin allows to manipulate the EKS Cluster on AWS

  This plugin requiere aws cli to be configured, for 'auto discovery' of
  the resources it will search for Subnets and Security groups with the
  tags

  kubernetes.io/cluster/cluster-name

  kubectl plugin eks-cluster create --cluster-name cluster-name
  kubectl plugin eks-cluster list
  kubectl plugin eks-cluster describe --cluster-name cluster-name
  kubectl plugin eks-cluster create --cluster-name cluster-name
EOF
} 

list_cluster() {
  echo "Available Clusters:"
  aws --region us-west-2 eks list-clusters --output text --query 'clusters[]'
}

help
list_cluster
exit 0
