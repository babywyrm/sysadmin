pipeline {
    agent {
        docker {
            image 'docker:20.10.24-dind-alpine3.17' // Alpine DIND container
            args '--privileged' // Required for Docker-in-Docker
        }
    }
    environment {
        IMAGE_NAME = "your-image:latest"
        TARBALL_PATH = "build/your-image.tar"
        TRIVY_REPORT = "trivy-report.json"
    }
    stages {
        stage('Set up Docker Environment') {
            steps {
                sh """
                # Initialize Docker-in-Docker service
                dockerd &

                # Wait for Docker to start
                while ! docker info >/dev/null 2>&1; do sleep 1; done
                """
            }
        }
        stage('Build Docker Image') {
            steps {
                sh """
                # Build the Docker image
                docker build -t ${IMAGE_NAME} .

                # Save the Docker image as a tarball
                docker save ${IMAGE_NAME} -o ${TARBALL_PATH}
                """
            }
        }
        stage('Install Trivy') {
            steps {
                sh """
                # Download and install the latest Trivy binary
                apk add --no-cache curl
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

                # Verify installation
                trivy --version
                """
            }
        }
        stage('Scan Docker Tarball with Trivy') {
            steps {
                sh """
                # Scan the Docker tarball with Trivy
                trivy image --input ${TARBALL_PATH} \
                    --format json --output ${TRIVY_REPORT}
                """
            }
        }
        stage('Publish Scan Results') {
            steps {
                script {
                    // Archive the Trivy report for auditing
                    archiveArtifacts artifacts: TRIVY_REPORT

                    // Optional: Analyze the report to fail the build based on vulnerabilities
                    def trivyReport = readJSON file: TRIVY_REPORT
                    if (trivyReport.Vulnerabilities) {
                        error "Trivy found vulnerabilities! Review the report."
                    } else {
                        echo "No vulnerabilities found."
                    }
                }
            }
        }
    }
    post {
        cleanup {
            sh 'docker system prune -af' // Cleanup Docker resources
        }
    }
}


/*
//
//

1. Docker-in-Docker Setup
The pipeline runs in a Docker DIND container (docker:20.10.24-dind-alpine3.17).
--privileged is required to enable Docker inside the container.
Starts the Docker daemon (dockerd &) and waits until it's ready.
2. Image Build and Export
The Docker image is built using docker build and saved as a tarball using docker save.
3. Trivy Installation
Trivy is installed directly within the container by downloading it from the official GitHub repository.
Uses a lightweight installation script compatible with Alpine.
4. Scanning with Trivy
Trivy scans the exported tarball with the --input flag, and outputs results in JSON format to trivy-report.json.
5. Publishing Results
The Trivy report is archived for further review.
Optionally, the pipeline can fail based on the presence of vulnerabilities.
6. Cleanup
Ensures Docker resources are cleaned up after the build process with docker system prune.

//
//
