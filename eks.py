#!/usr/bin/env python3
#
"""
EKS Plugin for KubeCtl

THIS IS A POC  IS NOT AT ALL FINISHED!!!!!!!!!


"""

import os
import logging
import argparse
import subprocess
import yaml
import boto3
import jmespath
#from botocore.exceptions import ClientError, ParamValidationError#, ResourceNotFoundException
#import botocore.errorfactory
global region
FORMAT = "%(levelname)s (Line: %(lineno)04d): %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
#logging.basicConfig(level=logging.DEBUG)
logging.getLogger('boto3').setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('requests').setLevel(logging.INFO)
# def getRegion(region='us-west-2'):
#   if os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_REGION'):
#     region = os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_REGION')
#   else:
#     logging.info("Using default us-west-2 region")
#   #Set the KUBECTL_PLUGINS_LOCAL_FLAG_REGION to the value of region
#   os.environ['KUBECTL_PLUGINS_LOCAL_FLAG_REGION'] = region
#   return region

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

def list_cluster():
  """
  List available clusters on the selected region
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


def getEksRole():
  """
  Search for the EKS role, by looking at all roles where service=eks.amazonaws.com and
  return the first one
  """
  iam = boto3.client('iam')
  roles = iam.list_roles()
  logging.debug('Searching for EKS Role')
  eks = jmespath.search("Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==`eks.amazonaws.com`]]| [0]| Arn", roles)
  logging.debug('EKS Role: %s', eks)
  return eks

def create_cluster(clusterName, subnets, securityGroups, roleArn):
  """
  Create the cluster by finding the Security Groups,Subnet and EKS Role
  This assume you have already created the requiered CloudFomration
  Templates needed for EKS.
  docs/eks/latest/userguide/getting-started.html
  """
  error_code = 0
  if subnets == "auto":
    logging.debug('using auto selection of subnets')
    subnets = getSubnets(clusterName)
  else:
    logging.debug('Using command parameters subnets')
    subnets = subnets.split(',')

  if securityGroups == "auto":
    securityGroups = getSecurityGroups(clusterName)
  else:
    securityGroups = securityGroups.split(',')
  if roleArn == "auto":
    roleArn = getEksRole()
  else:
    roleArn = roleArn
  if not subnets:
    logging.error('No Subnet Discovered')
    error_code = 1
  if not securityGroups:
    logging.error('No Security Group Discovered')
    error_code = 1
  if not roleArn:
    logging.error('No EKS Role discovered')
    error_code = 1

  if error_code != 0:
    logging.critical('Error creating the cluster, some parameters are missing')
    exit(1)

  logging.debug('Subnets        : %s', subnets)
  logging.debug('Security Groups: %s', securityGroups)
  print(subnets, " ", securityGroups, " ", roleArn)
  eks = boto3.client('eks', region_name=region)
  try:
    status = eks.create_cluster(clusterName=clusterName,
                                roleArn=roleArn,
                                subnets=subnets,
                                securityGroups=securityGroups)
  except Exception as exception:
    #logging all the others as warning
    logging.critical("Failed. %s", format(exception))
    exit(99)
  print(status['cluster'])
  return status['cluster']

def describe_cluster(clusterName, verbose='yes', output=True):
  """
  This will return basic information on the cluster, or can return a
  more detailed information depending on the verbose parameter.
  Verbose can be 'no','yes' or 'cert'
  """
  eks = boto3.client('eks', region_name=region)
  try:
    cluster = eks.describe_cluster(clusterName=clusterName)
  except Exception as exception:
    #logging all the others as warning
    logging.critical("Failed. %s", format(exception))
    exit(99)
  cluster = cluster['cluster']
  #print(json.dumps(cluster,indent=2))
  if output:
    print("Cluster name......: %s" % cluster['clusterName'])
    print("Master Version....: %s" % cluster['desiredMasterVersion'])
    print("Master Endpoint...: %s" % cluster['masterEndpoint'])
    print("Cluster Status....: %s" % cluster['status'])
    if verbose != 'no':
      print("Subnets...........: %s" % ','.join(cluster['subnets']))
      print("Security Groups...: %s" % ','.join(cluster['securityGroups']))
      print("EKS Role Arn......: %s" % cluster['roleArn'])
    if verbose == 'cert':
      print("Certificate Data..: %s" % cluster['certificateAuthority']['data'])
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
    logging.debug("No Such Cluster on the kubeconfig, Configuring...")
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
    logging.warning("No Such context configured, Configuring...")
    context = {'name': contextName, 'context': {'cluster': clusterName, 'user': username}}
    #logging.info("Cluster: %s", context)
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
  logging.info("kubeconfig file created on ~/.kube/config-aws")

def delete_cluster(cluster_name):
  """
  This function calls delete_cluster to remove the clusterName
  """
  eks = boto3.client('eks', region_name=region)
  try:
    cluster = eks.delete_cluster(clusterName=cluster_name)
  except Exception as exception:
    #logging all the others as warning
    logging.critical("Failed. %s", format(exception))
    exit(99)
  cluster = cluster['cluster']
  print("Deleting cluster %s (Status=%s)" % (cluster['clusterName'], cluster['status']))
  return cluster

def main():
  global region
  parser = argparse.ArgumentParser()
  parser.add_argument("-r", "--region",
                      dest="region",
                      help="AWS Region",
                      default=os.environ.get(
                          'KUBECTL_PLUGINS_LOCAL_FLAG_DESIRED_MASTER_VERSION',
                          "us-west-2"))
  subparsers = parser.add_subparsers(title="Available commands", dest='cmd')
  ## List Clusters
  parser_list = subparsers.add_parser('list', help="Show Available Clusters")
  parser_list.set_defaults(func=list_cluster)

  parser_help = subparsers.add_parser('help', help="Show Help")
  ## Create a EKS Cluster
  parser_create = subparsers.add_parser('create', help="Create EKS Cluster")
  parser_create.add_argument('--cluster-name',
                             dest='clusterName',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME', None))
  parser_create.add_argument('--subnets',
                             dest='subnets',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_SUBNETS', None))
  parser_create.add_argument('--security-groups',
                             dest='securityGroups',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_SECURITY_GROUPS', None))
  parser_create.add_argument('--role-arn',
                             dest='roleArn',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_ROLE_ARN', None))
  parser_create.add_argument('--desired-master-version',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_DESIRED_MASTER_VERSION', None))
  ## Describe a EKS Cluster
  parser_describe = subparsers.add_parser('describe', help="Describe an EKS Cluster")
  parser_describe.add_argument('--cluster-name', dest='clusterName',
                               default=os.environ.get(
                                   'KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME', None))
  parser_describe.add_argument('--detail',
                               choices=['no', 'yes', 'cert'],
                               default=os.environ.get(
                                   'KUBECTL_PLUGINS_LOCAL_FLAG_DETAIL', 'no'))
  parser_describe.set_defaults(func=describe_cluster)

  ## Delete a EKS Cluster
  parser_delete = subparsers.add_parser('delete', help="Delete an EKS Cluster")
  parser_delete.add_argument('--cluster-name', dest='clusterName',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME', None))

  ## Generate EKS Cluster Config
  parser_genconf = subparsers.add_parser('generate-config', help="Create kubeconfig for EKS Cluster")
  parser_genconf.add_argument('--cluster-name', dest='clusterName',
                              default=os.environ.get(
                                  'KUBECTL_PLUGINS_LOCAL_FLAG_CLUSTER_NAME', None))

  args = parser.parse_args()
  region = args.region
  #parser.print_help()
  if args.cmd == "list":
    args.func()
  elif args.cmd == "help":
    parser.print_help()
  elif args.cmd == "create":
    create_cluster(clusterName=args.clusterName,
                   subnets=args.subnets,
                   securityGroups=args.securityGroups,
                   roleArn=args.roleArn)
  elif args.cmd == "describe":
    if args.clusterName == '':
      logging.critical('No Cluster Name Specified, Exiting....')
      parser_describe.print_help()
      exit()
    args.func(args.clusterName, args.detail)
  elif args.cmd == "delete":
    delete_cluster(cluster_name=args.clusterName)
  elif args.cmd == "generate-config":
    generate_kubeconfig(args.clusterName)
  #print (args)
  #args_list = parser_list.parse_args()
  #print (args_list)
  exit(0)
  #print(getRegion())
  #print(getSecurityGroups(clusterName='demo1',region=region))
  #print(getSubnets('demo1'))
  #print(getEksRole())
  #create_cluster('demo2'),region=region)
  # region=getregion()
  # #help()
  #list_cluster()
  #create_cluster('demo1')
  generate_kubeconfig(clusterName='demo2')

if __name__ == '__main__':
  #getRegion()
  main()
