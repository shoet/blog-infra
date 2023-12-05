#!/bin/bash

sudo yum update -y

# Install git
sudo yum install -y git

# Install Node.js
sudo yum install -y nodejs
sudo npm install -g n
sudo n latest

# Install Docker
sudo yum install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -a -G docker ec2-user

# mysql client
sudo yum -y localinstall https://dev.mysql.com/get/mysql80-community-release-el9-5.noarch.rpm
sudo yum install mysql-community-client -y

