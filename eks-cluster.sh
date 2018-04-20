#!/bin/bash

list_cluster() {
  echo "Available Clusters:"
  aws --region us-west-2 eks list-clusters --output text --query 'clusters[]'
}

list_cluster
exit 0
