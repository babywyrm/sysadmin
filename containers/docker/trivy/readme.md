
##
#
https://stackoverflow.com/questions/77084998/how-to-use-trivy-with-jenkins-running-on-docker-container
#
https://semaphoreci.com/blog/continuous-container-vulnerability-testing-with-trivy
#
https://medium.com/@lilnya79/integrating-jenkins-with-trivy-222eaa7a70be
#
https://github.com/aquasecurity/trivy/issues/3660
#
https://github.com/GandhiCloudLab/devsecops-with-trivy/#1-Integrating-Trivy-in-Jenkins
#
##

```
version: '3'
services:

  # Jenkins Service
  jenkins:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - JENKINS_HOME=/var/jenkins_home
      - JENKINS_ADMIN_ID=admin
      - JENKINS_ADMIN_PASSWORD=password
      - SERVER_IP=${server_ip}
      - DOCKER_USERNAME=${docker_username}
      - DOCKER_PASSWORD=${docker_password}
      - GITHUB_USERNAME=${github_username}
      - GITHUB_PASSWORD=${github_password}
      - GITHUB_ACCESS_TOKEN=${github_access_token}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - jenkins_home:/var/jenkins_home
      - /usr/bin/docker:/usr/bin/docker

  # Trivy Service
  trivy:
    image: aquasec/trivy:latest
    volumes:
      - trivy-cache:/root/.cache/
      - /var/run/docker.sock:/var/run/docker.sock

  # SonarQube Service
  sonarqube:
    image: sonarqube:latest
    ports:
      - "9000:9000"
      - "9092:9092"
    volumes:
      - sonarqube_data:/opt/sonarqube/data

volumes:
  # Jenkins Home Volume
  jenkins_home:

  # SonarQube Data Volume
  sonarqube_data:

  # Trivy Cache Volume
  trivy-cache:

```


Integrating Jenkins with Trivy
Liliane Konissi

Introduction:

In modern software development workflows, Continuous Integration/Continuous Deployment (CI/CD) pipelines are essential for maintaining agility and efficiency. However, security vulnerabilities in container images can pose significant risks. Integrating Jenkins with Trivy, a popular vulnerability scanner for containers, enhances security by automatically scanning container images for vulnerabilities as part of the CI/CD process. In this guide, we’ll walk through the step-by-step process of integrating Jenkins with Trivy to bolster the security of your software development pipeline.
Step 1: Install Jenkins

1.1. Download and install Jenkins on your server or preferred environment. Refer to the official Jenkins documentation for detailed installation instructions based on your operating system.
Step 2: Set Up Trivy

2.1. Install Trivy on the system where Jenkins is running. You can find installation instructions on the Trivy GitHub repository or official documentation.

2.2. Ensure Trivy is accessible from the command line by testing its installation with a simple command, such as trivy --version.
Step 3: Scan a docker image using Freestyle job

    Create New Job: Click on “New Item” on the left sidebar to create a new job.
    Choose Freestyle Project: Enter a name for the job and select “Freestyle project” as the project type.
    Configure General Settings: Optionally configure general settings such as description and discard old builds.
    Source Code Management (Optional): Configure source code management if your job requires it, providing repository URL and credentials if needed.
    Build Triggers (Optional): Set up build triggers to automate job execution based on events like SCM changes or time schedule.
    Build Environment (Optional): Configure build environment settings like parameters and concurrency.
    Add Build Step: Scroll down to the “Build” section and add a build step. Choose “Execute shell” for Unix-like systems or “Execute Windows batch command” for Windows systems.
    Write Shell Script: In the provided text area, write the shell commands you want Jenkins to execute as part of the job.Enter the Trivy command to scan your container images. For example:

trivy image --severity HIGH,CRITICAL <your-container-image>

Replace <your-container-image> with the image you want to scan. You can specify additional options as needed, such as setting thresholds for vulnerabilities severity.

Save Configuration: Save the job configuration after adding the shell script.

Trigger a build manually or wait for the next scheduled build to run.

Jenkins will now execute the configured Trivy command as part of the build process, scanning the specified container image for vulnerabilities.
Step 4: Scan a docker image using Pipeline job

pipeline {
    agent any 

    environment {
        DOCKERHUB_CREDENTIALS = credentials('your-docker-credentials')
        APP_NAME = "laly9999/lil-node-app"
    }

    stages { 
        stage('SCM Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/lily4499/lil-node-app.git'
            }
        }
        
        stage('Build docker image') {
            steps {  
                sh 'docker build -t $APP_NAME:latest .'
            }
        }
        
       stage('Scan Docker Image') {
            steps {
                script {
                    // Run Trivy to scan the Docker image
                    def trivyOutput = sh(script: "trivy image $APP_NAME:latest", returnStdout: true).trim()

                    // Display Trivy scan results
                    println trivyOutput

                    // Check if vulnerabilities were found
                    if (trivyOutput.contains("Total: 0")) {
                        echo "No vulnerabilities found in the Docker image."
                    } else {
                        echo "Vulnerabilities found in the Docker image."
                        // You can take further actions here based on your requirements
                        // For example, failing the build if vulnerabilities are found
                        // error "Vulnerabilities found in the Docker image."
                    }
                }
            }
        }
    }
}

Make sure to replace your_image_name and your_credentials with the name of your Docker image and your DockerHub credentials ID..
Step 5: Review Trivy Scan Results

5.1. Once the Jenkins job completes, navigate to the job’s build page.

5.2. Look for the Trivy scan results either in the console output or in a separate report generated by the Trivy plugin.

5.3. Analyze the vulnerabilities detected by Trivy and take appropriate actions to address them, such as updating dependencies or adjusting security policies.
Conclusion:

Integrating Jenkins with Trivy empowers your CI/CD pipeline with automated security scanning, helping you detect and mitigate vulnerabilities in container images early in the development process. By following this step-by-step guide, you can strengthen the security posture of your software delivery pipeline and ensure that only secure container images are deployed into production environments.

