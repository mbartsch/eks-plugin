#!/usr/bin/python3
#
"""
EKS Plugin for KubeCtl
"""
import boto3
import os
import logging
import json
import jmespath
import base64
#import yaml

FORMAT = "%(lineno)d %(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT)

def getRegion():
  global region
  region=os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_REGION')
  if not region:
    logging.info("No region specified asusming default us-west-2")
    region='us-west-2'
  """
  Set the KUBECTL_PLUGINS_LOCAL_FLAG_REGION to the value of region
  """
  os.environ['KUBECTL_PLUGINS_LOCAL_FLAG_REGION'] = region
  return region

def getclusterName():
  """
  This will read the environment varible KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME
  to use it as cluster name and return it
  """
  cluster_name=os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME')
  if not cluster_name:
    logging.error("No cluster specified")
    #exit(2)
  return cluster_name



def help():
  print("This plugin allows to manipulate the EKS Cluster on AWS")
  print("This plugin requiere aws cli to be configured, for 'auto discovery' of the resources it will search for Subnets and Security groups with the tags")
  print("\n")
  print("kubernetes.io/cluster/cluster-name")
  print("\n")
  print("kubectl plugin eks-cluster create --cluster-name cluster-name")
  print("kubectl plugin eks-cluster list")
  print("kubectl plugin eks-cluster describe --cluster-name cluster-name")
  print("kubectl plugin eks-cluster create --cluster-name cluster-name")

def list_cluster():
  """
  List available clusters on the region
  """
  eks=boto3.client('eks',region_name=region)
  clusters=eks.list_clusters()
  print("Available Clusters")
  for cluster in clusters['clusters']:
    print("Name: %s" % cluster)

def getSecurityGroups(clusterName):
  """
  Search for the security groups tagged with kubernetes.io/cluster/cluster-name
  and return them
  """
  secgroups=[]
  ec2=boto3.client('ec2',region_name=region)
  tagname="tag:kubernetes.io/cluster/" + clusterName
  sgs=ec2.describe_security_groups(Filters=[{'Name':tagname,'Values':['owned','shared']}])
  for sg in sgs['SecurityGroups']:
    secgroups.append(sg['GroupId'])
  return secgroups

def getSubnets(clusterName):
  """
  Search for the subnets tagged with kubernetes.io/cluster/cluster-name
  and return them
  """
  subnets=[]
  ec2=boto3.client('ec2',region_name=region)
  tagname="tag:kubernetes.io/cluster/" + clusterName
  snet=ec2.describe_subnets(Filters=[{'Name':tagname,'Values':['owned','shared']}])
  for sn in snet['Subnets']:
    subnets.append(sn['SubnetId'])
  return subnets

"""
Search for the EKS role, by looking at all roles where service=eks.amazonaws.com and
return the first one
"""
def getEksRole():
  iam=boto3.client('iam')
  roles=iam.list_roles()
  eks=jmespath.search("Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==`eks.amazonaws.com`]]| [0]| Arn",roles)
  return eks

def create_cluster(clusterName,region):
  """
  Create the cluster by finding the Security Groups,Subnet and EKS Role
  This assume you have already created the requiered CloudFomration
  Templates needed for EKS.
  docs/eks/latest/userguide/getting-started.html
  """
  subnets=getSubnets(clusterName)
  secgroups=getSecurityGroups(clusterName)
  eksrole=getEksRole()
  if not subnets:
    print('No Subnet Discovered')
  if not secgroups:
    print('No Security Group Discovered')
  if not eksrole:
    print('No EKS Role discovered')
  
  print (subnets," ", secgroups," ",eksrole)
  eks=boto3.client('eks',region_name=region)
  status=eks.create_cluster(clusterName=clusterName,
    roleArn=eksrole,
    subnets=subnets,
    securityGroups=secgroups)
  print(status)
  return(status)

def describe_cluster(clusterName,verbose='yes'):
  eks=boto3.client('eks',region_name=region)
  cluster=eks.describe_cluster(clusterName=clusterName)
  cluster=cluster['cluster']
  #print(json.dumps(cluster,indent=2))
  print("Cluster name......: %s" % cluster['clusterName'])
  print("Master Version....: %s" % cluster['desiredMasterVersion'])
  print("Master Endpoint...: %s" % cluster['masterEndpoint'])
  print("Cluster Status....: %s" % cluster['status'])
  if (verbose != 'no'):
    print("Subnets...........: %s" % ' '.join(cluster['subnets']))
    print("Security Groups...: %s" % ' '.join(cluster['securityGroups']))
    print("EKS Role Arn......: %s" % cluster['roleArn'])
  if (verbose == 'cert'):
    print("Certificate Data..: %s" % cluster['certificateAuthority']['data'])
  return cluster

def main():
  #print(getRegion())
  #print(getSecurityGroups(clusterName='demo1',region=region))
  #print(getSubnets('demo1'))
  #print(getEksRole())
  #create_cluster('demo2',region=region)
  # region=getregion()
  # #help()
  #list_cluster()
  describe_cluster('demo',verbose='yes')
if __name__ == '__main__':
  getRegion()
  main()

