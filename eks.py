#!/usr/bin/env python3
#
"""
EKS Plugin for KubeCtl

THIS IS A POC  IS NOT AT ALL FINISHED!!!!!!!!!


"""

import argparse
import logging
import os
import subprocess
import json

import boto3
import jmespath
import yaml

#from botocore.exceptions import ClientError, ParamValidationError#, ResourceNotFoundException
#import botocore.errorfactory
global REGION
FORMAT = "%(levelname)s (Line: %(lineno)04d): %(message)s"
FORMAT = "%(asctime)s - %(name)s - (Line: %(lineno)04d) - %(levelname)s - %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

#logging.basicConfig(level=logging.DEBUG)
logging.getLogger(__name__)
logging.getLogger('boto3').setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('requests').setLevel(logging.INFO)
def getRegion(region='us-west-2'):
  if os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_REGION'):
    region = os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_REGION')
  else:
    logging.info("Using default us-west-2 region")
  #Set the KUBECTL_PLUGINS_LOCAL_FLAG_REGION to the value of region
  os.environ['KUBECTL_PLUGINS_LOCAL_FLAG_REGION'] = region
  return region

def get_cluster_name():
  """
  This will read the environment varible KUBECTL_PLUGINS_LOCAL_FLAG_NAME
  to use it as cluster name and return it
  """
  cluster_name = os.getenv('KUBECTL_PLUGINS_LOCAL_FLAG_NAME')
  if not cluster_name:
    logging.error("No cluster specified")
    #exit(2)
  return cluster_name

def list_cluster():
  """
  List available clusters on the selected region
  """
  eks = boto3.client('eks', region_name=REGION)
  clusters = eks.list_clusters()
  print("Available Clusters")
  for cluster in clusters['clusters']:
    print("Name: %s" % cluster)
  return clusters['clusters']

def get_security_groups(cluster_name):
  """
  Search for the security groups tagged with kubernetes.io/cluster/cluster-name
  and return them
  """
  secgroups = []
  ec2 = boto3.client('ec2', region_name=REGION)
  tagname = "tag:kubernetes.io/cluster/" + cluster_name
  sgs = ec2.describe_security_groups(Filters=[{'Name':tagname, 'Values':['owned', 'shared']}])
  for security_group in sgs['SecurityGroups']:
    secgroups.append(security_group['GroupId'])
  return secgroups

def get_subnets(cluster_name):
  """
  Search for the subnets tagged with kubernetes.io/cluster/cluster-name
  and return them
  """
  subnets = []
  ec2 = boto3.client('ec2', region_name=REGION)
  tagname = "tag:kubernetes.io/cluster/" + cluster_name
  snet = ec2.describe_subnets(Filters=[{'Name':tagname, 'Values':['owned', 'shared']}])
  for subnet in snet['Subnets']:
    subnets.append(subnet['SubnetId'])
  return subnets


def get_role_arn():
  """
  Search for the EKS role, by looking at all roles where service=eks.amazonaws.com and
  return the first one
  """
  iam = boto3.client('iam')
  roles = iam.list_roles()
  logging.debug('Searching for EKS Role')
  eks = jmespath.search("Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service"
                        + "==`eks.amazonaws.com`]]| [0]| Arn", roles)
  logging.debug('EKS Role: %s', eks)
  return eks

def create_cluster(cluster_name, subnets, security_groups, role_arn):
  """
  Create the cluster by finding the Security Groups,Subnet and EKS Role
  This assume you have already created the requiered CloudFomration
  Templates needed for EKS.
  docs/eks/latest/userguide/getting-started.html
  """
  error_code = 0
  if subnets == "auto":
    logging.debug('using auto selection of subnets')
    subnets = get_subnets(cluster_name)
  else:
    logging.debug('Using command parameters subnets')
    subnet_list = subnets.split(',')

  if security_groups == "auto":
    security_groups = get_security_groups(cluster_name)
  else:
    security_group_list = security_groups.split(',')
  if role_arn == "auto":
    role_arn = get_role_arn()
  else:
    role_arn = role_arn
  if not subnets:
    logging.error('No Subnet Discovered')
    error_code = 1
  if not security_groups:
    logging.error('No Security Group Discovered')
    error_code = 1
  if not role_arn:
    logging.error('No EKS Role discovered')
    error_code = 1

  if error_code != 0:
    logging.critical('Error creating the cluster, some parameters are missing')
    exit(1)

  logging.debug('Subnets        : %s', subnet_list)
  logging.debug('Security Groups: %s', security_group_list)
  print(subnets, " ", security_groups, " ", role_arn)
  eks = boto3.client('eks', region_name=REGION)
  try:
    status = eks.create_cluster(name=cluster_name,
                                roleArn=role_arn,
                                resourcesVpcConfig={'subnetIds': subnet_list, 'securityGroupIds': security_group_list})
  except Exception as exception:
    #logging all the others as warning
    logging.critical("Failed. %s", format(exception))
    exit(99)
  print(status['cluster'])
  logging.debug('Tagging subnets')
  for subnet in subnets:
    try:
      tag_resources(cluster_name,subnet)
    except Exception as exception:
      #logging all the others as warning
      logging.critical("Failed tagging subnet. %s", format(exception))
      exit(99)

  return status['cluster']

def describe_cluster(cluster_name, verbose='yes', output=True):
  """
  This will return basic information on the cluster, or can return a
  more detailed information depending on the verbose parameter.
  Verbose can be 'no','yes' or 'cert'
  """
  eks = boto3.client('eks', region_name=REGION)
  try:
    cluster = eks.describe_cluster(name=cluster_name)
  except Exception as exception:
    #logging all the others as warning
    logging.critical("Failed. %s", format(exception))
    exit(99)
  cluster = cluster['cluster']
  #print(json.dumps(cluster,indent=2))
  if output:
    print("Cluster name......: %s" % cluster['name'])
    print("Master Version....: %s" % cluster['version'])
    print("Cluster Status....: %s" % cluster['status'])
    if cluster['status'] == 'ACTIVE':
      print("Master Endpoint...: %s" % cluster['endpoint'])
    elif cluster['status'] == 'DELETING':
      print("Master Endpoint...: CLUSTER_IN_DELETING_STATE")
    else:
      print("Master Endpoint...: CLUSTER_IN_CREATING_STATE")
    if verbose != 'no':
      print("Created At........: %s" % cluster['createdAt'])
      print("Subnets...........: %s" % ','.join(cluster['resourcesVpcConfig']['subnetIds']))
      print("Security Groups...: %s" % ','.join(cluster['resourcesVpcConfig']['securityGroupIds']))
      print("VPC ID............: %s" % cluster['resourcesVpcConfig']['vpcId'])
      print("EKS Role Arn......: %s" % cluster['roleArn'])
    if verbose == 'cert' and cluster['status'] == 'ACTIVE':
      print("Certificate Data..: %s" % cluster['certificateAuthority']['data'])
    elif verbose == 'cert':
      print("Certificate Data..: CLUSTER_IN_CREATING_STATE")
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
  cluster_name = kconfig['name']
  cluster_info = kconfig['clusterinfo']
  clusters = [cluster for cluster in kconfig['clusters'] if cluster.get('name') == cluster_name]
  if clusters:
    index = 0
    for cluster in kconfig['clusters']:
      if cluster['name'] == cluster_name:
        #logging.warn(yaml.dump(cluster,indent=2))
        logging.debug("Found Cluster Update it")
        server = cluster_info['endpoint']
        certauthdata = cluster_info['certificateAuthority']['data']
        cluster['cluster'] = {'certificate-authority-data': certauthdata, 'server': server}
      index = index + 1
      #logging.warn(cluster)
  else:
    logging.debug("No Such Cluster on the kubeconfig, Configuring...")
    clusterdata = {'certificate-authority-data': cluster_info['certificateAuthority']['data'],
                   'server': cluster_info['endpoint']}
    cluster = {'name': cluster_name, 'cluster': clusterdata}
    #logging.info("Cluster: %s" , cluster)
    kconfig['clusters'].append(dict(cluster))
  return kconfig

def generate_context_config(kconfig):
  """
  Context Definition
  """
  #print(kconfig)
  cluster_name = kconfig['name']
  #clusterinfo = kconfig['clusterinfo']
  context_name = "k8s-aws-" + cluster_name
  username = cluster_name + "-admin"
  context = [context for context in kconfig['contexts'] if context.get('name') == context_name]
  if context:
    logging.debug('Context 1 : %s', context)
    index = 0
    for context in kconfig['contexts']:
      logging.debug('context found %s', context)
      if context['name'] == context_name:
        logging.debug('context found')
        context['context'] = {'cluster': cluster_name, 'user': username}
        index = index + 1
      logging.debug(context)
  else:
    logging.warning("No Such context configured, Configuring...")
    context = {'name': context_name, 'context': {'cluster': cluster_name, 'user': username}}
    #logging.info("Cluster: %s", context)
    kconfig['contexts'].append(dict(context))
  return kconfig

def generate_users_config(kconfig):
  """
  User section
  """
  cluster_name = kconfig['name']
  #clusterinfo = kconfig['clusterinfo']
  username = cluster_name + "-admin"
  userdata = [user for user in kconfig['users'] if user.get('name') == username]
  if userdata:
    index = 0
    for user in kconfig['users']:
      #print(user['name'])
      if user['name'] == username:

        #print (kconfig['users'].index({'name':username}))
        args = ["token", "-i", cluster_name]
        execparms = {'apiVersion':'client.authentication.k8s.io/v1alpha1',
                     'args': args,
                     'command': 'heptio-authenticator-aws'}
        user = {'name': username, 'user': {'exec': execparms}}
        kconfig['users'][index] = user
      index = index + 1
    #logging.debug (kconfig['users'])
  else:
    args = ["token", "-i", cluster_name]
    execparms = {'apiVersion':'client.authentication.k8s.io/v1alpha1',
                 'args': args, 'command': 'heptio-authenticator-aws',
                 'env': None}
    user = {'name': username, 'user': {'exec': execparms}}
    kconfig['users'].append(dict(user))
    #kconfig['users'][pos]['name'] = username
    #print(kconfig['users'])
    #print(yaml.dump(kconfig))

  return kconfig
def generate_kubeconfig(cluster_name):
  """
  Generate the kubeconfig file, currently will read the configuration from
  ~/.kube/config or KUBECONFIG variable, using kubectl and will wrote the
  configuration to ~/.kube/config-aws

  """
  from pathlib import Path
  if cluster_name == "":
    logging.error('No Cluster Name Provided')
    exit()
  clusterinfo = describe_cluster(cluster_name, output=False)
  kconfig = read_kubectlconfig()
  kconfig['clusterinfo'] = dict(clusterinfo)
  kconfig['name'] = cluster_name
  #print(yaml.dump(kconfig,indent=2,default_flow_style=False))
  kconfig = generate_cluster_config(kconfig)
  kconfig = generate_context_config(kconfig)
  kconfig = generate_users_config(kconfig)
  del kconfig['clusterinfo']
  del kconfig['name']
  print(yaml.dump(kconfig, indent=2, default_flow_style=False))
  homedir = str(Path.home())
  kubeaws = homedir + "/.kube/config-aws"
  with open(kubeaws, mode='w') as kubecfg:
    kubecfg.write(yaml.dump(kconfig, indent=2, default_flow_style=False))
  kubecfg.close()
  logging.info("kubeconfig file created on ~/.kube/config-aws")

def delete_cluster(cluster_name,remove_tags=True):
  """
  This function calls delete_cluster to remove the name
  """
  eks = boto3.client('eks', region_name=REGION)
  clusterInfo = describe_cluster(cluster_name=cluster_name,output=False)
  
  try:
    cluster = eks.delete_cluster(name=cluster_name)
  except Exception as exception:
    logging.critical("Failedto delete cluster %s. %s", cluster_name, format(exception))
    exit(99)
  print("Deleting cluster %s (Status=%s)" % (cluster['cluster']['name'], cluster['cluster']['status']))
  if remove_tags:
    for subnet in clusterInfo['resourcesVpcConfig']['subnetIds']:
      logging.debug('Remove tag from subnet %s', subnet)
      tag_resources(clusterInfo['name'], subnet, remove=True)
  
  return cluster


def tag_resources(cluster_name, resource, shared=True, remove=False):
  """
  This function will tag the given subnet with the kubernetes.io/cluster/cluster
  with a value of shared by default unless shared is False when calling the function
  """
  if shared:
    shared = 'shared'
  else:
    shared = 'owned'
  ec2 = boto3.client('ec2', region_name=REGION)
  if remove:
    ec2.delete_tags(Resources=[resource],
                    Tags=[{'Key':'kubernetes.io/cluster/' + cluster_name,
                           'Value':shared}])
  else:
    ec2.create_tags(Resources=[resource],
                    Tags=[{'Key':'kubernetes.io/cluster/' + cluster_name,
                           'Value':shared}])

def main():
  """
  Main function
  """
  global REGION

  parser = argparse.ArgumentParser()
  parser.add_argument("-r", "--region",
                      dest="REGION",
                      help="AWS Region",
                      default=os.environ.get(
                          'KUBECTL_PLUGINS_LOCAL_FLAG_REGION',
                          "us-west-2"))
  subparsers = parser.add_subparsers(title="Available commands", dest='cmd')
  ## List Clusters
  parser_list = subparsers.add_parser('list', help="Show Available Clusters")
  parser_list.set_defaults(func=list_cluster)

  parser_help = subparsers.add_parser('help', help="Show Help")
  parser_help.set_defaults()
  ## Create a EKS Cluster
  parser_create = subparsers.add_parser('create', help="Create EKS Cluster")
  parser_create.add_argument('--name',
                             dest='name',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_NAME', None))
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
  parser_describe.add_argument('--name', dest='name',
                               default=os.environ.get(
                                   'KUBECTL_PLUGINS_LOCAL_FLAG_NAME', None))
  parser_describe.add_argument('--detail',
                               choices=['no', 'yes', 'cert'],
                               dest='detail',
                               default=os.environ.get(
                                   'KUBECTL_PLUGINS_LOCAL_FLAG_DETAIL', 'no'))
  parser_describe.set_defaults(func=describe_cluster)

  ## Delete a EKS Cluster
  parser_delete = subparsers.add_parser('delete', help="Delete an EKS Cluster")
  parser_delete.add_argument('--name', dest='name',
                             default=os.environ.get(
                                 'KUBECTL_PLUGINS_LOCAL_FLAG_NAME', None))
  #parser_delete.add_argument('--clean-subnet', dest='clean_subnet',
  #                           default=os.environ.get(
  #                               'KUBECTL_PLUGINS_LOCAL_FLAG_CLEAN', None))

  ## Generate EKS Cluster Config
  parser_genconf = subparsers.add_parser('generate-config',
                                         help="Create kubeconfig for EKS Cluster")
  parser_genconf.add_argument('--name', dest='name',
                              default=os.environ.get(
                                  'KUBECTL_PLUGINS_LOCAL_FLAG_NAME', None))
  ## General AWS Commands that are handy
  parser_aws = subparsers.add_parser('aws-tag', help="Command to manage the AWS Infrastructure")
  parser_aws.add_argument('--name', dest='name',
                          default=os.environ.get(
                              'KUBECTL_PLUGINS_LOCAL_FLAG_NAME', None))
  parser_aws.add_argument('--resource', dest='resource',
                          default=os.environ.get('KUBECTL_PLUGINS_LOCAL_FLAG_RESOURCE', None))
  parser_aws.add_argument('--remove', dest='remove', default=False, action='store_true')
  args = parser.parse_args()
  #print(args)
  REGION = args.REGION
  #parser.print_help()
  if args.cmd == "list":
    args.func()
  elif args.cmd == "help":
    parser.print_help()
  elif args.cmd == "create":
    create_cluster(cluster_name=args.name,
                   subnets=args.subnets,
                   security_groups=args.securityGroups,
                   role_arn=args.roleArn)
  elif args.cmd == "describe":
    if args.name == '':
      logging.critical('No Cluster Name Specified, Exiting....')
      parser_describe.print_help()
      exit()
    print(args.name)
    args.func(args.name, args.detail)
  elif args.cmd == "delete":
    delete_cluster(cluster_name=args.name)
  elif args.cmd == "generate-config":
    generate_kubeconfig(args.name)
  elif args.cmd == "aws-tag":
    print(args)
    if os.environ.get('KUBECTL_PLUGINS_LOCAL_FLAG_REMOVE', '') != '':
      args.remove = True
    if not args.resource:
      logging.critical('No Resource passed')
      exit()
    print(args)
    tag_resources(cluster_name=args.name, resource=args.resource, remove=args.remove)


if __name__ == '__main__':
  main()
