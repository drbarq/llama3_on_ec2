"""
AWS EC2 Management Script

This script automates the deployment and management of an AWS EC2 instance with specific configurations,
including setting up a VPC, security group, IAM roles, and installing necessary software on the instance.
It also includes monitoring and automatic shutdown capabilities.

Ensure that you have `boto3`, `paramiko`, `python-dotenv`, and `cryptography` libraries installed.
Set up AWS credentials with appropriate permissions.
Create a `.env` file with `DATADOG_API_KEY` and `KEY_FILENAME` variables.
"""

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import boto3
import time
import paramiko
import threading
from threading import Timer
import sys
import os
import json
from datetime import datetime
import signal
import os
from dotenv import load_dotenv


load_dotenv()

# SSH into the Instance:
# ssh -i /path/to/your/key.pem ec2-user@<instance-public-ip>
# Tail the Log File:
# tail -f /var/log/user-data.log

# AWS configuration
region = 'us-west-2'  # Change this to your desired region
instance_type = 'g4dn.xlarge'
datadog_api_key = os.getenv("DATADOG_API_KEY")
key_filename_location = os.getenv("KEY_FILENAME")

# Shutdown configuration
max_runtime = 3600  # Maximum runtime in seconds (e.g., 1 hour)
inactivity_threshold = 3600  # Inactivity threshold in seconds (10 minutes)

# EC2, VPC, and IAM clients
ec2 = boto3.client('ec2', region_name=region)
ec2_resource = boto3.resource('ec2', region_name=region)
iam = boto3.client('iam')


def get_or_create_vpc():
    """
    Creates a new VPC if none exists, including an Internet Gateway, route table, and subnet.
    Returns the VPC ID.
    """
    existing_vpcs = list(ec2_resource.vpcs.all())
    if existing_vpcs:
        return existing_vpcs[0].id

    vpc = ec2_resource.create_vpc(CidrBlock='10.0.0.0/16')
    vpc.wait_until_available()
    vpc.create_tags(Tags=[{"Key": "Name", "Value": "OllamaVPC"}])

    ig = ec2_resource.create_internet_gateway()
    vpc.attach_internet_gateway(InternetGatewayId=ig.id)

    route_table = vpc.create_route_table()
    route_table.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=ig.id)

    subnet = ec2_resource.create_subnet(VpcId=vpc.id, CidrBlock='10.0.1.0/24')
    route_table.associate_with_subnet(SubnetId=subnet.id)

    ec2.modify_subnet_attribute(SubnetId=subnet.id, MapPublicIpOnLaunch={'Value': True})

    print(f"Created new VPC: {vpc.id}")
    return vpc.id


def create_iam_role():
    """
    Creates an IAM role with AmazonS3FullAccess policy for EC2 instances if it does not already exist.
    Returns the role name.
    """
    role_name = 'EC2InstanceRoleWithS3Access'
    try:
        # Check if the role already exists
        iam.get_role(RoleName=role_name)
        print(f"IAM role {role_name} already exists.")
    except iam.exceptions.NoSuchEntityException:
        # Create the role
        trust_relationship = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_relationship)
        )
        print(f"Created IAM role: {role_name}")

        # Attach the AmazonS3FullAccess policy
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AmazonS3FullAccess'
        )
        print(f"Attached AmazonS3FullAccess policy to {role_name}")

        # Create an instance profile and add the role to it
        iam.create_instance_profile(InstanceProfileName=role_name)
        iam.add_role_to_instance_profile(
            InstanceProfileName=role_name,
            RoleName=role_name
        )
        print(f"Created instance profile and added role {role_name}")

        # Wait for the instance profile to be ready
        time.sleep(10)

    return role_name


def get_latest_amazon_linux_2_ami():
    """
    Retrieves the latest Amazon Linux 2 AMI ID.
    """
    response = ec2.describe_images(
        Owners=['amazon'],
        Filters=[
            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
            {'Name': 'state', 'Values': ['available']},
        ],
    )
    return sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']


def detach_volumes(instance_id):
    """
    Detaches all volumes attached to a specified EC2 instance.
    """
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}])['Volumes']
        for volume in volumes:
            ec2.detach_volume(VolumeId=volume['VolumeId'], InstanceId=instance_id, Force=True)
            print(f"Detached volume {volume['VolumeId']} from instance {instance_id}.")
    except Exception as e:
        print(f"Error detaching volumes: {e}")


def delete_volumes(instance_id):
    """
    Deletes all volumes attached to a specified EC2 instance.
    """
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}])['Volumes']
        for volume in volumes:
            ec2.delete_volume(VolumeId=volume['VolumeId'])
            print(f"Deleted volume {volume['VolumeId']}.")
    except Exception as e:
        print(f"Error deleting volumes: {e}")


def detach_and_delete_volumes(instance_id):
    """
    Detaches and then deletes all volumes attached to a specified EC2 instance.
    """
    detach_volumes(instance_id)
    time.sleep(10)  # Wait for volumes to detach before deleting
    delete_volumes(instance_id)


def create_security_group(vpc_id):
    """
    Creates a new security group in the specified VPC with predefined ingress rules.
    Returns the security group details.
    """
    try:
        security_group = ec2.create_security_group(
            GroupName='OllamaSecurityGroup',
            Description='Security group for Ollama instance',
            VpcId=vpc_id
        )
        ec2.authorize_security_group_ingress(
            GroupId=security_group['GroupId'],
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 11434, 'ToPort': 11434, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 3000, 'ToPort': 3000, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ]
        )
        print(f"Created new security group: {security_group['GroupId']}")
        return security_group
    except ec2.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
            print("Security group already exists. Using existing group.")
            security_groups = ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': ['OllamaSecurityGroup']}]
            )
            return security_groups['SecurityGroups'][0]
        else:
            raise


def create_key_pair(key_name):
    """
    Creates a new key pair for SSH access if it does not already exist.
    Returns the key name.
    """
    try:
        key_pair = ec2.create_key_pair(KeyName=key_name)
        private_key = key_pair['KeyMaterial']

        with open(f"{key_name}.pem", 'w') as key_file:
            key_file.write(private_key)

        os.chmod(f"{key_name}.pem", 0o400)
        print(f"Created new key pair: {key_name}")
        return key_name
    except ec2.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
            print(f"Key pair {key_name} already exists. Using existing key.")
            return key_name
        else:
            raise


def launch_ec2_instance(ami_id, instance_type, subnet_id, security_group_id, key_name, iam_role_name, datadog_api_key):
    """
    Launches an EC2 instance with the specified configuration, including user data for initial setup.
    Returns the instance details.
    """
    try:
        print(f"Attempting to launch instance of type {instance_type}")
        response = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[{
                'SubnetId': subnet_id,
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': True,
                'Groups': [security_group_id]
            }],
            BlockDeviceMappings=[{
                'DeviceName': '/dev/xvda',
                'Ebs': {
                    'VolumeSize': 100,
                    'VolumeType': 'gp3',
                    'DeleteOnTermination': True
                }
            }],
            IamInstanceProfile={'Name': iam_role_name},
            UserData=f'''#!/bin/bash
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting UserData script"

# Update and install dependencies
sudo yum update -y
sudo yum install -y gcc make kernel-devel-$(uname -r) aws-cli docker

echo "Dependencies installed"

# Install NVIDIA GRID Drivers
cd /home/ec2-user
aws s3 cp --recursive s3://ec2-linux-nvidia-drivers/latest/ .
chmod +x NVIDIA-Linux-x86_64*.run
sudo mkdir -p /home/ec2-user/tmp
sudo chmod -R 777 /home/ec2-user/tmp
sudo su -c "TMPDIR=/home/ec2-user/tmp ./NVIDIA-Linux-x86_64*.run --silent"
echo "options nvidia NVreg_EnableGpuFirmware=0" | sudo tee --append /etc/modprobe.d/nvidia.conf

echo "NVIDIA GRID Drivers installed"

# Start and enable Docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user

echo "Docker installed and started"

# Install NVIDIA Container Toolkit
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/nvidia-container-toolkit.repo | sudo tee /etc/yum.repos.d/nvidia-container-toolkit.repo
sudo yum install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

echo "NVIDIA Container Toolkit installed"

# Create Docker network
sudo docker network create ollama-network

# Install Ollama Server
sudo docker run -d --gpus=all -v ollama:/root/.ollama -p 11434:11434 --name ollama --network ollama-network --restart unless-stopped ollama/ollama

echo "Ollama server installed"

# Pull and run the LLM model
sudo docker exec ollama ollama pull llama3.1:8b
sudo docker exec ollama ollama run llama3.1:8b "Hello, World!" > /dev/null 2>&1

echo "LLM model downloaded and initialized"

# Get Ollama container IP
OLLAMA_IP=$(sudo docker inspect -f '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' ollama)
echo "OLLAMA_IP: $OLLAMA_IP"  # Debug line to print the IP address

# Install Ollama Web UI
sudo docker run -d -p 3000:8080 \
  --add-host=host.docker.internal:$OLLAMA_IP \
  -e OLLAMA_API_BASE_URL=http://ollama:11434/api \
  -e DEFAULT_MODELS=llama3.1:8b \
  -v ollama-webui:/app/backend/data \
  --name ollama-webui \
  --network ollama-network \
  --restart unless-stopped \
  ghcr.io/open-webui/open-webui:main

echo "Ollama Web UI installed"

# Install Datadog Agent
DD_AGENT_MAJOR_VERSION=7 DD_API_KEY={datadog_api_key} DD_SITE="datadoghq.com" bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent7.sh)"

# Configure Datadog to tail log files
sudo tee /etc/datadog-agent/datadog.yaml > /dev/null <<EOF
logs_enabled: true

logs:
  - type: file
    path: /var/log/user-data.log
    service: ollama-ec2
    source: user-data
EOF

sudo systemctl restart datadog-agent

echo "Datadog Agent installed and configured to tail logs"

echo "UserData script completed"
'''
        )
        return response['Instances'][0]
    except ec2.exceptions.ClientError as e:
        print(f"Error launching instance: {e}")
        sys.exit(1)


def get_instance_public_ip(instance_id):
    """
    Retrieves the public IP address of a specified EC2 instance.
    """
    max_retries = 10
    retry_delay = 10
    for _ in range(max_retries):
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        if 'PublicIpAddress' in instance_info['Reservations'][0]['Instances'][0]:
            return instance_info['Reservations'][0]['Instances'][0]['PublicIpAddress']
        print("Waiting for public IP assignment...")
        time.sleep(retry_delay)
    print("Failed to obtain a public IP address. Please check your VPC and subnet settings.")
    sys.exit(1)


def check_ollama_status(ssh_client):
    """
    Checks if the Ollama Docker container is running on the EC2 instance via SSH.
    """
    try:
        stdin, stdout, stderr = ssh_client.exec_command('docker ps | grep ollama')
        return stdout.channel.recv_exit_status() == 0
    except Exception as e:
        print(f"Error checking Ollama status: {e}")
        return False


def shutdown_instance(instance_id):
    """
    Shuts down the specified EC2 instance.
    """
    print("Shutting down the instance...")
    ec2.stop_instances(InstanceIds=[instance_id])
    waiter = ec2.get_waiter('instance_stopped')
    waiter.wait(InstanceIds=[instance_id])
    print("Instance stopped.")


def monitor_instance(instance_id, public_ip):
    """
    Monitors the EC2 instance for activity and shuts it down based on inactivity or maximum runtime.
    Establishes an SSH connection to the instance.
    """
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    key = paramiko.RSAKey.from_private_key_file(key_filename_location)

    max_retries = 30
    retry_interval = 10

    for attempt in range(max_retries):
        try:
            print(f"Attempting SSH connection (attempt {attempt + 1}/{max_retries})...")
            ssh_client.connect(public_ip, username='ec2-user', pkey=key, timeout=30)
            print("SSH connection established")
            break
        except Exception as e:
            print(f"Failed to connect via SSH: {e}")
            time.sleep(retry_interval)
    else:
        print(f"Failed to connect via SSH after {max_retries} attempts. Shutting down.")
        shutdown_instance(instance_id)
        return

    start_time = time.time()
    last_activity = start_time

    while True:
        current_time = time.time()

        if current_time - start_time > max_runtime:
            print("Maximum runtime exceeded. Shutting down.")
            break

        if check_ollama_status(ssh_client):
            last_activity = current_time
        else:
            if current_time - last_activity > inactivity_threshold:
                print("Inactivity threshold exceeded. Shutting down.")
                break
 
        time.sleep(60)  # Check every minute

    ssh_client.close()
    shutdown_instance(instance_id)


def terminate_instance(instance_id):
    """
    Terminates the specified EC2 instance and deletes attached volumes.
    """
    print(f"Terminating instance {instance_id}...")
    try:
        shutdown_instance(instance_id)
        detach_and_delete_volumes(instance_id)
        ec2.terminate_instances(InstanceIds=[instance_id])
        print(f"Instance {instance_id} termination request sent.")
    except Exception as e:
        print(f"Error terminating instance: {e}")


def terminate_instance_after_timer(instance_id):
    """
    Terminates the specified EC2 instance after a set timer (1 hour).
    """
    print(f"Terminating instance {instance_id} after 1 hour")
    terminate_instance(instance_id)
    print("Instance termination initiated, exiting the script.")
    os._exit(0)


def signal_handler(signum, frame):
    """
    Handles termination signals (SIGINT, SIGTERM) to gracefully shut down the instance.
    """
    print("\nReceived signal to terminate. Shutting down the instance...")
    if 'instance_id' in globals():
        terminate_instance(instance_id)
    sys.exit(0)


def main():
    """
    Main function to execute the workflow: create VPC, security group, key pair, IAM role, launch EC2 instance, and monitor it.
    """
    global instance_id  # Make instance_id global so it can be accessed by the signal handler

    vpc_id = get_or_create_vpc()
    ami_id = get_latest_amazon_linux_2_ami()
    print(f"Using AMI: {ami_id}")

    security_group = create_security_group(vpc_id)

    subnets = list(ec2_resource.subnets.filter(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]))
    if not subnets:
        print("No subnet found. Please check your VPC configuration.")
        sys.exit(1)
    subnet_id = subnets[0].id

    key_name = create_key_pair("OllamaKeyPair")

    iam_role_name = create_iam_role()

    instance = launch_ec2_instance(ami_id, instance_type, subnet_id, security_group['GroupId'], key_name, iam_role_name, datadog_api_key)
    instance_id = instance['InstanceId']
    print(f"Instance {instance_id} of type {instance['InstanceType']} has been created.")

    print("Waiting for the instance to enter 'running' state...")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])

    print("Waiting for instance to initialize...")

    public_ip = get_instance_public_ip(instance_id)
    print(f"Instance is now running. Public IP: {public_ip}")
    print(f"Ollama server should be available at http://{public_ip}:11434")
    print(f"Ollama Web UI should be available at http://{public_ip}:3000")
    print(f"Please allow a few minutes for all services to start up completely. The time is is {datetime.now()}")

    monitor_thread = threading.Thread(target=monitor_instance, args=(instance_id, public_ip))
    monitor_thread.start()

    print("Instance is now being monitored. It will shut down automatically based on the specified conditions.")
    print("You can now use the instance. Remember to save your work before the automatic shutdown.")
    print("Press Ctrl+C to exit the script and terminate the instance.")

    # Set a timer to terminate the instance after 1 hour (3600 seconds)
    print("The instance will automatically terminate in 1 hour.")
    timer = Timer(3600, terminate_instance_after_timer, [instance_id])
    timer.start()

    try:
        monitor_thread.join()
    except KeyboardInterrupt:
        print("\nScript interrupted. Terminating the instance...")
        terminate_instance(instance_id)

    print("Script execution completed.")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()
