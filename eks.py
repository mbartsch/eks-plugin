#!/usr/bin/python3
#
"""
EKS Plugin for KubeCtl

THIS IS A POC  IS NOT AT ALL FINISHED!!!!!!!!!


"""

import os
import logging
#import json
#import base64
#import tempfile
import subprocess
import yaml
import boto3
import jmespath
#import kubeconfig

FORMAT = "%(levelname)s (%(lineno)d): %(message)s"
logging.basicConfig(format=FORMAT)

def getRegion():
  global region
  region = os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_REGION')
  if not region:
    logging.warning("No region specified asusming default us-west-2")
    region = 'us-west-2'
  #Set the KUBECTL_PLUGINS_LOCAL_FLAG_REGION to the value of region
  os.environ['KUBECTL_PLUGINS_LOCAL_FLAG_REGION'] = region
  return region

def getclusterName():
  """
  This will read the environment varible KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME
  to use it as cluster name and return it
  """
  cluster_name = os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME')
  if not cluster_name:
    logging.error("No cluster specified")
    #exit(2)
  return cluster_name


def ekshelp():
  print("This plugin allows to manipulate the EKS Cluster on AWS")
  print("This plugin requiere aws cli to be configured, for 'auto discovery'")
  print("of the resources it will search for Subnets and Security groups with the tags")
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
  eks = boto3.client('eks', region_name=region)
  clusters = eks.list_clusters()
  print("Available Clusters")
  for cluster in clusters['clusters']:
    print("Name: %s" % cluster)

def getSecurityGroups(clusterName):
  """
  Search for the security groups tagged with kubernetes.io/cluster/cluster-name
  and return them
  """
  secgroups = []
  ec2 = boto3.client('ec2', region_name=region)
  tagname = "tag:kubernetes.io/cluster/" + clusterName
  sgs = ec2.describe_security_groups(Filters=[{'Name':tagname, 'Values':['owned', 'shared']}])
  for sg in sgs['SecurityGroups']:
    secgroups.append(sg['GroupId'])
  return secgroups

def getSubnets(clusterName):
  """
  Search for the subnets tagged with kubernetes.io/cluster/cluster-name
  and return them
  """
  subnets = []
  ec2 = boto3.client('ec2', region_name=region)
  tagname = "tag:kubernetes.io/cluster/" + clusterName
  snet = ec2.describe_subnets(Filters=[{'Name':tagname, 'Values':['owned', 'shared']}])
  for sn in snet['Subnets']:
    subnets.append(sn['SubnetId'])
  return subnets

"""
Search for the EKS role, by looking at all roles where service=eks.amazonaws.com and
return the first one
"""
def getEksRole():
  iam = boto3.client('iam')
  roles = iam.list_roles()
  eks = jmespath.search("Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==`eks.amazonaws.com`]]| [0]| Arn", roles)
  return eks

def create_cluster(clusterName):
  """
  Create the cluster by finding the Security Groups,Subnet and EKS Role
  This assume you have already created the requiered CloudFomration
  Templates needed for EKS.
  docs/eks/latest/userguide/getting-started.html
  """
  subnets = getSubnets(clusterName)
  secgroups = getSecurityGroups(clusterName)
  eksrole = getEksRole()
  if not subnets:
    print('No Subnet Discovered')
  if not secgroups:
    print('No Security Group Discovered')
  if not eksrole:
    print('No EKS Role discovered')

  print(subnets, " ", secgroups, " ", eksrole)
  eks = boto3.client('eks', region_name=region)
  status = eks.create_cluster(clusterName=clusterName,
                              roleArn=eksrole,
                              subnets=subnets,
                              securityGroups=secgroups)
  print(status)
  return status

def describe_cluster(clusterName, verbose='yes', output=True):
  """
  This will return basic information on the cluster, or can return a
  more detailed information depending on the verbose parameter.
  Verbose can be 'no','yes' or 'cert'
  """
  eks = boto3.client('eks', region_name=region)
  cluster = eks.describe_cluster(clusterName=clusterName)
  cluster = cluster['cluster']
  #print(json.dumps(cluster,indent=2))
  if output:
    logging.info("Cluster name......: %s", cluster['clusterName'])
    logging.info("Master Version....: %s", cluster['desiredMasterVersion'])
    logging.info("Master Endpoint...: %s", cluster['masterEndpoint'])
    logging.info("Cluster Status....: %s", cluster['status'])
    if verbose != 'no':
      logging.info("Subnets...........: %s", ' '.join(cluster['subnets']))
      logging.info("Security Groups...: %s", ' '.join(cluster['securityGroups']))
      logging.info("EKS Role Arn......: %s", cluster['roleArn'])
    if verbose == 'cert':
      logging.info("Certificate Data..: %s", cluster['certificateAuthority']['data'])
  return cluster

def read_kubectlconfig():
  """
  This funciton will execute kubectl and return the output as a yaml object
  """
  conf = subprocess.Popen('kubectl config view --raw=true --merge=true',
                          stdout=subprocess.PIPE, shell=True)
  (output, err) = conf.communicate()
  if err:
    logging.error(err)
  conf.wait()
  config = yaml.load(output)
  conf.terminate()
  return config


def generate_cluster_config(kconfig):
  """
  Cluster Section
  """
  clusterName = kconfig['clusterName']
  clusterinfo = kconfig['clusterinfo']
  clusters = [cluster for cluster in kconfig['clusters'] if cluster.get('name') == clusterName]
  if clusters:
    index = 0
    for cluster in kconfig['clusters']:
      if cluster['name'] == clusterName:
        #logging.warn(yaml.dump(cluster,indent=2))
        logging.debug("Found Cluster Update it")
        server = clusterinfo['masterEndpoint']
        certauthdata = clusterinfo['certificateAuthority']['data']
        cluster['cluster'] = {'certificate-authority-data': certauthdata, 'server': server}
      index = index + 1
      #logging.warn(cluster)
  else:
    logging.debug("No Such Cluster, Creating it")
    clusterdata = {'certificate-authority-data': clusterinfo['certificateAuthority']['data'],
                   'server': clusterinfo['masterEndpoint']}
    cluster = {'name': clusterName, 'cluster': clusterdata}
    #logging.info("Cluster: %s" , cluster)
    kconfig['clusters'].append(dict(cluster))
  return kconfig

def generate_context_config(kconfig):
  """
  Context Definition
  """
  #print(kconfig)
  clusterName = kconfig['clusterName']
  #clusterinfo = kconfig['clusterinfo']
  contextName = "k8s-aws-" + clusterName
  username = clusterName + "-admin"
  context = [context for context in kconfig['contexts'] if context.get('name') == contextName]
  if context:
    logging.debug('Context 1 : %s', context)
    index = 0
    for context in kconfig['contexts']:
      logging.debug('context found %s', context)
      if context['name'] == contextName:
        logging.debug('context found')
        context['context'] = {'cluster': clusterName, 'user': username}
        index = index + 1
      logging.debug(context)
  else:
    logging.warning("No Such Cluster, Creating it")
    context = {'name': contextName, 'context': {'cluster': clusterName, 'user': username}}
    logging.info("Cluster: %s", context)
    kconfig['contexts'].append(dict(context))
  return kconfig

def generate_users_config(kconfig):
  """
  User section
  """
  clusterName = kconfig['clusterName']
  #clusterinfo = kconfig['clusterinfo']
  username = clusterName + "-admin"
  userdata = [user for user in kconfig['users'] if user.get('name') == username]
  if userdata:
    index = 0
    for user in kconfig['users']:
      #print(user['name'])
      if user['name'] == username:

        #print (kconfig['users'].index({'name':username}))
        args = ["token", "-i", clusterName]
        execparms = {'apiVersion':'client.authentication.k8s.io/v1alpha1',
                     'args': args,
                     'command': 'heptio-authenticator-aws'}
        user = {'name': username, 'user': {'exec': execparms}}
        kconfig['users'][index] = user
      index = index + 1
    #logging.debug (kconfig['users'])
  else:
    #logging.info ("No such User")
    # userblock="""name: """+ username + """,user: exec: apiVersion: client.authentication.k8s.io/v1alpha1,args: [token, -i, """ + clusterName + """],command: heptio-authenticator-aws,env: None"""
    # print(userblock)
    #pos = int(len(kconfig['users']))
    #logging.info("Position: %s"%pos)
    args = ["token", "-i", clusterName]
    execparms = {'apiVersion':'client.authentication.k8s.io/v1alpha1',
                 'args': args, 'command': 'heptio-authenticator-aws',
                 'env': None}
    user = {'name': username, 'user': {'exec': execparms}}
    kconfig['users'].append(dict(user))
    #kconfig['users'][pos]['name'] = username
    #print(kconfig['users'])
    #print(yaml.dump(kconfig))

  return kconfig

def generate_kubeconfig(clusterName):
  """
  Generate the kubeconfig file, currently will read the configuration from
  ~/.kube/config or KUBECONFIG variable, using kubectl and will wrote the
  configuration to ~/.kube/config-aws

  """
  from pathlib import Path

  clusterinfo = describe_cluster(clusterName, output=False)
  kconfig = read_kubectlconfig()
  kconfig['clusterinfo'] = dict(clusterinfo)
  kconfig['clusterName'] = clusterName
  #print(yaml.dump(kconfig,indent=2,default_flow_style=False))
  kconfig = generate_cluster_config(kconfig)
  kconfig = generate_context_config(kconfig)
  kconfig = generate_users_config(kconfig)
  del kconfig['clusterinfo']
  del kconfig['clusterName']
  print(yaml.dump(kconfig, indent=2, default_flow_style=False))
  homedir = str(Path.home())
  kubeaws = homedir + "/.kube/config-aws"
  with open(kubeaws, mode='w') as kubecfg:
    kubecfg.write(yaml.dump(kconfig, indent=2, default_flow_style=False))
  kubecfg.close()


def main():
  #print(getRegion())
  #print(getSecurityGroups(clusterName='demo1',region=region))
  #print(getSubnets('demo1'))
  #print(getEksRole())
  #create_cluster('demo2'),region=region)
  # region=getregion()
  # #help()
  #list_cluster()
  create_cluster('demo1')
  generate_kubeconfig(clusterName='demo2')

if __name__ == '__main__':
  getRegion()
  main()
