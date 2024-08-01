# EC2 Automation and Ollama with LLaMA 3.1 8B and Instruct FP16

This repository contains scripts to automate the creation of an Amazon EC2 instance and deploy Ollama with LLaMA 3.1 8B and Instruct FP16 models. The scripts help in setting up the environment, launching the EC2 instance, and running the models.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Scripts](#scripts)
  - [main8b.py](#main8bpy)
  - [main8b-instruct-fp16.py](#main8b-instruct-fp16py)
- [Usage](#usage)
- [Cleaning Up](#cleaning-up)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

Before running the scripts, ensure you have the following prerequisites:

1. **AWS Account**: You need an AWS account to create and manage EC2 instances.
2. **AWS CLI**: Install the AWS Command Line Interface and configure it with your credentials.
3. **Python 3.6+**: Ensure you have Python installed on your local machine.
4. **Required Packages**: Install required Python packages using pip:

   ```bash
   pip install -r requirements.txt
   ```

5. **IAM Role**: Ensure you have the necessary permissions to create and manage EC2 instances.

## Setup

1. **Clone the Repository**:

   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Install Required Packages**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure AWS CLI**:

   ```bash
   aws configure
   ```

## Scripts

### main8b.py

This script automates the setup and execution of the LLaMA 3.1 8B model on an EC2 instance. It includes the following steps:

- Creating an EC2 instance.
- Setting up the environment (installing dependencies, setting up Ollama).
- Running the LLaMA 3.1 8B model.

The instance will automatically terminate when the script is closed using a signal (e.g., pressing Ctrl+C) or after one hour.

### main8b-instruct-fp16.py

This script follows similar steps as `main8b.py` but is specifically tailored for running the LLaMA 3.1 8B Instruct model with FP16 precision.

The instance will automatically terminate when the script is closed using a signal (e.g., pressing Ctrl+C) or after one hour.

## Usage

1. **Run the LLaMA 3.1 8B Script**:

   ```bash
   python main8b.py
   ```

2. **Run the LLaMA 3.1 8B Instruct Script**:

   ```bash
   python main8b-instruct-fp16.py
   ```

Both scripts will:

- Launch an EC2 instance.
- Connect to the instance.
- Install necessary dependencies.
- Deploy and run the specified LLaMA model.

## Cleaning Up

To avoid incurring unnecessary charges, ensure you terminate the EC2 instances after use. You can do this manually through the AWS Management Console, by using the signal (Ctrl+C) to close the script, or after the automatic shutdown after one hour.

## Troubleshooting

- **EC2 Instance Not Launching**: Verify your AWS credentials and permissions.
- **Dependencies Not Installing**: Check the network connectivity and the availability of the package repositories.
- **Model Not Running**: Ensure that the instance type has sufficient resources to run the models.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
