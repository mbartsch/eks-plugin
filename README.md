# eks plugin for kubectl 
This plugin allows to create, delete and display the information for a EKS Cluster from the kubectl tool

## Requirements
* bash shell
* aws cli
* jq


# THIS IS THE DEVEL VERSION INFO BELOW IS NOT ACCURATE

## Installation

To install this plugin , clone this git repository to $HOME/.kube/plugins

```
mkdir $HOME/.kube/plugins
cd $HOME/.kube/plugins
git clone ssh://git.amazon.com/pkg/Kubectl-eks-plugin eks-plugin
```

## Usage
Currently the plugin will allow to list, create, describe and delete a EKS cluster

By default 'kubectl plugin eks' will list the cluster on the account
* Show help and current clusters
```
kubectl plugin eks
```
* List Cluster on the account
```
kubectl plugin eks list
```

* Describe Cluster
```
kubectl plugin eks describe [--cluster-name=demo][--detail=yes|cert]
```

* Delete a cluster
```
kubectl plugin eks delete [--cluster-name=demo]
```
* Generate kubeconfig output
```
kubectl plugin eks genconf [--cluster-name=demo]
```

* Usage help
```
kubectl plugin eks --help
```
### Manage EKS Cluster Worker AutoScaling Groups
* List Available AutoScaling Group(s)
```
kubectl plugin eks asg
```
  * Modify the AutoScaling Group
```
kubectl plugin eks asg [--asg-name=ASGName][--cluster-name=cluster-name][--desired=num][--min=num][--max=num][--region=region]
```


Create a Cluster
* the plugin will search for security groups and subnets with the tag 'kubernetes.io/cluster/cluster_name' and use those as parameters to create it
* the Arn for the role is also discovered
  * The Discover process look for a IAM Profile that has the trust relationship with eks.amazonaws.com

```
kubectl plugin eks --action=create --cluster-name=demo
```

## Todo
- [x] Move it to use 'trees' instead of a single command
- [ ] error handling
- [ ] Auto configure $HOME/.kube/config
  - [x] Create the output to be place in $KUBECONFIG to stdout
- [ ] Write the plugin in python to be more portable
    - [ ] boto3 issue is blocking this problem.
