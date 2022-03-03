# Instructions for using this repository

Follow the instructions below to setup the demo using Jenkins on your machine.

## 1. Install Tomcat

Download and unzip [Tomcat 9](https://dlcdn.apache.org/tomcat/tomcat-9/v9.0.58/bin/apache-tomcat-9.0.58.zip)

## 2. Install Jenkins

- Download [Jenkins.war](https://get.jenkins.io/war/2.335/jenkins.war)
- Copy the .war file to `/apache-tomcat/webapps` folder

## 3. Start Tomcat

`$>cd /apache-tomcat`
`$>chmod u+x ./bin/*.sh`
`$>./bin/startserver.sh`

## 4. Access Jenkins

Open URL in browser: `http://localhost:8080/jenkins`
