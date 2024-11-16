#!/usr/bin/env groovy

final List<String> environments = Env.values().collect() { it.name() }

pipeline {
    agent {
        label any
    }
  
    parameters {
        string(name: 'currentk8sVersion', defaultValue: '', description: 'Provide the k8s Major & Minor version to upgrade from e.g. 1.18')
        choice(name: 'Env', choices: environments, description: 'Environment to upgrade')
    }
  
    stages {
      
        stage('List Clusters') {
            steps {
                awsAuthentication()
                echo 'Successfully logged to AWS'
                script {
                    String cluster = awsCluster(params.Env.trim().toLowerCase())
                    echo '${cluster}'
                    connectToEksCluster(cluster.trim(), "us-east-1")
                }
            }
        }
      
        stage('Check K8s and nodes version') {
            steps {
                echo 'Checking k8s version of Cluster'
                script {
                    try {
                        sh '''
                            kubectl version --short
                            kubectl get nodes 
                        '''
                    } catch(err){
                        echo err.toString()
                    }
                }
            }
        }
        
        stage('EKS priviliged policy') {
            steps {
                echo 'Make sure EKS priviliged policy exists'
                script {
                    try {
                        sh 'kubectl get psp eks.privileged'
                    } catch(err) {
                        echo err.toString()
                    }
                }
            }
        }
        
        stage('Disable cluster autoscaler') {
            steps {
                echo 'Disable cluster autoscaler'
                script {
                    try {
                        sh 'kubectl scale deployments/cluster-autoscaler --replicas=0 -n kube-system'
                    } catch(err) {
                        echo err.toString()
                    }
                }
            }
        }
        
        stage('Autoscale Nodes') {
            steps {
                  script {
                    try{
                        sh """#!/bin/bash
                        cluster_name=`kubectl config current-context | cut -d '/' -f2`
                        echo "\${cluster_name}"  
                        
                        worker_tag=`echo "\${cluster_name}" | sed s/"-cluster"//` 
                        echo "\${worker_tag}"
                        
                        auto_scaling_group_name=`aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[? Tags[? (Key=='Name') && Value=='\${worker_tag}-workers']]".AutoScalingGroupName --profile saml --output text` 
                        echo "\${auto_scaling_group_name}"
                        
                        actual_capacity=`aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[? Tags[? (Key=='Name') && Value=='\${worker_tag}-workers']]".DesiredCapacity --profile saml --output text`
                        echo "\${actual_capacity}"
                        
                        desired_capacity=`expr "\${actual_capacity}" \\* 2`
                        echo "\${desired_capacity}"
                        
                        max_capacity=`aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[? Tags[? (Key=='Name') && Value=='\${worker_tag}-workers']]".MaxSize --profile saml --output text`
                        echo "\${max_capacity}"
                        
                        if [ \${desired_capcity} >= \${max_capacity} ]
                        then
                            max_size=`expr "\${max_capacity}" \\* 2`
                            aws autoscaling  update-auto-scaling-group --auto-scaling-group-name \${auto_scaling_group_name} --max-size \${max_size} --profile=saml
                        fi
                        
                        aws autoscaling set-desired-capacity --auto-scaling-group-name \${auto_scaling_group_name} --desired-capacity \${desired_capacity} --profile=saml 
                        """
                    } catch (err) {
                        echo err.toString()
                    }
                 }
            }
        }
        
        stage('Taint Nodes') {
            steps {
                  script {
                    try{
                        sh """    
                        echo "k8 version is ${params.currentk8sVersion}"
                        export PATH=$PATH:/tools/jq/jq-1.5/jq 
                        nodes=`kubectl get nodes -o json | jq -r '.items[] | select(.status.nodeInfo.kubeletVersion | contains(\"v${params.currentk8sVersion}\")) | .metadata.name' | tr '\n' ' '`
                        
                        echo "\${nodes}"
                        for node in \${nodes[@]}
                        do
                            echo "Tainting \$node"
                            kubectl taint nodes \$node key=value:NoSchedule
                        done 
                        """
                    } catch (err) {
                        echo err.toString()
                    }
                }
            }
        }
        
        stage('Drain Nodes') {
            input {
                  message "Do you want to proceed to Drain the old nodes ?"
            }  
            
            steps {
                sh """    
                  echo "k8 version is ${params.currentk8sVersion}"
                  export PATH=$PATH:/tools/jq/jq-1.5/jq 
                  nodes=`kubectl get nodes -o json | jq -r '.items[] | select(.status.nodeInfo.kubeletVersion | contains(\"v${params.currentk8sVersion}\")) | .metadata.name' | tr '\n' ' '`
                  echo "\${nodes}"
                  for node in \${nodes[@]}
                  do
                    echo "Draining \$node"
                    kubectl drain \$node --ignore-daemonsets --delete-emptydir-data --force
                    echo "Sleeping for 5 mins to allow pod startups in new node"
                    sleep 300
                  done 
                """ 
            }
        }
        
        stage('Validate Pods') {
            steps {
               sh """    
                  kubectl get pods --field-selector=status.phase!=Running --all-namespaces
                """     
            }
        }
        
        stage('Terminate Old Nodes') {
            input {
                  message "Do you want to proceed for terminate of old nodes ?"
            }
            
            steps {                 
               sh """#!/bin/bash 
                  echo "k8 version is ${params.currentk8sVersion}"
                  export PATH=$PATH:/tools/jq/jq-1.5/jq
                  nodes=`kubectl get nodes -o json | jq -r '.items[] | select(.status.nodeInfo.kubeletVersion | contains(\"v${params.currentk8sVersion}\")) | .spec.providerID' | sed "s/.*\\(i-.*\\)/\\1/" | tr '\n' ' '`
                  echo "\${nodes}"
                  for node in \${nodes[@]}
                  do
                     echo "Terminating \$node"
                     aws autoscaling terminate-instance-in-auto-scaling-group --instance-id \$node --should-decrement-desired-capacity --profile=saml
                 done
                """
            }
        }
        
        stage('Enable cluster autoscaler') {
            steps {
                echo 'Enable cluster autoscaler'
                script {
                    try {
                        sh 'kubectl scale deployments/cluster-autoscaler --replicas=1 -n kube-system'
                    } catch(err) {
                        echo err.toString()
                    }
                }
            }
        }
        
        stage('Upgrade VPC CNI Plugin') {
            steps {
                echo 'Update cni plugin'
                script {
                    try {
                        sh 'kubectl apply -f addons/vpc-cni/1.7.10/aws-k8s-cni.yaml'
                    } catch(err) {
                        echo err.toString
                    }
                }
            }
        }
        
        stage('Upgrade Core DNS version') {
            steps {
                echo 'update dns version'
                script {
                    try {
                        sh 'kubectl set image --namespace kube-system deployment.apps/coredns coredns=602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/coredns:v1.8.0-eksbuild.1'
                    } catch(err) {
                        echo err.toString
                    }
                }
            }
        }
        
        stage('Upgrade the Kube Proxy Plugin') {
            steps {
                echo 'Upgrade the Kube Proxy Plugin'
                script {
                    try {
                        sh 'kubectl set image daemonset.apps/kube-proxy -n kube-system kube-proxy=602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/kube-proxy:v1.19.6-eksbuild.2'
                    } catch(err) {
                        echo err.toString
                    }
               }
            }
        }
    }
}

private void connectToEksCluster(String cluster, String region) {
    sh 'aws eks --region ' + region + ' update-kubeconfig --name ' + cluster + ' --profile=saml'
}
