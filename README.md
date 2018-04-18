# eks plugin for kubectl 
This plugin allows to create, delete and display the information for a EKS Cluster from the kubectl tool

## Requirements
* bash shell
* aws cli

## Installation

To install this plugin , clone this git repository to $HOME/.kube/plugins

```
mkdir $HOME/.kube/plugins
cd $HOME/.kube/plugins
git clone ssh://git.amazon.com/pkg/Kubectl-eks-plugin eks-plugin
```

## Usage
Currently the plugin will allow to list, create, describe and delete a EKS cluster

## Todo
- [ ] error handling
- [ ] auto configure $HOME/.kube/config
- [ ] Write the plugin in python to be more portable
    - [ ] boto3 issue is blocking this problem.
