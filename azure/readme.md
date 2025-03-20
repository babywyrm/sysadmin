# Azure vs AWS - Core Services Comparison

## Compute Services

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Virtual Machines | Azure Virtual Machines | Amazon EC2 | IaaS compute resources | ```az vm create --resource-group myRG --name myVM --image UbuntuLTS --admin-username azureuser --generate-ssh-keys``` | ```aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t2.micro --key-name MyKeyPair``` |
| Autoscaling | Virtual Machine Scale Sets | EC2 Auto Scaling | Automatically adjust compute capacity | ```az vmss create --resource-group myRG --name myScaleSet --image UbuntuLTS --upgrade-policy-mode automatic --instance-count 3 --admin-username azureuser --generate-ssh-keys``` | ```aws autoscaling create-auto-scaling-group --auto-scaling-group-name my-asg --min-size 1 --max-size 3 --launch-template LaunchTemplateName=my-template,Version='$Latest'``` |

## Storage Services

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Object Storage | Azure Blob Storage | Amazon S3 | Store unstructured data | ```az storage blob upload --account-name mystorageacct --container-name mycontainer --name myblob --file myfile.txt``` | ```aws s3 cp myfile.txt s3://mybucket/myfile.txt``` |
| File Storage | Azure Files | Amazon EFS | Managed file shares | ```az storage share create --account-name mystorageacct --name myfileshare --quota 1024``` | ```aws efs create-file-system --performance-mode generalPurpose --throughput-mode bursting``` |
| Disk Storage | Azure Managed Disks | Amazon EBS | Block storage for VMs | ```az disk create --resource-group myRG --name myDisk --size-gb 128``` | ```aws ec2 create-volume --availability-zone us-west-2a --size 80``` |

## Database Services

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Relational DB | Azure SQL Database | Amazon RDS | Managed relational databases | ```az sql server create --name myserver --resource-group myRG --location westus --admin-user myadmin --admin-password P@ssw0rd1``` | ```aws rds create-db-instance --db-instance-identifier mydbinstance --db-instance-class db.t3.micro --engine mysql --master-username admin --master-user-password password --allocated-storage 20``` |
| NoSQL | Azure Cosmos DB | Amazon DynamoDB | NoSQL database services | ```az cosmosdb create --name mycosmosdb --resource-group myRG --kind MongoDB``` | ```aws dynamodb create-table --table-name Music --attribute-definitions AttributeName=Artist,AttributeType=S --key-schema AttributeName=Artist,KeyType=HASH --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5``` |
| Cache | Azure Cache for Redis | Amazon ElastiCache | In-memory caching | ```az redis create --name myRedisCache --resource-group myRG --location westus --sku Basic --vm-size C0``` | ```aws elasticache create-cache-cluster --cache-cluster-id my-cluster --engine redis --cache-node-type cache.t3.micro --num-cache-nodes 1``` |

## Networking Services

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Virtual Network | Azure Virtual Network | Amazon VPC | Isolated network environment | ```az network vnet create --name myVNet --resource-group myRG --subnet-name default --subnet-prefix 10.0.0.0/24``` | ```aws ec2 create-vpc --cidr-block 10.0.0.0/16``` |
| Load Balancer | Azure Load Balancer | Elastic Load Balancing | Distribute network traffic | ```az network lb create --resource-group myRG --name myLoadBalancer --frontend-ip-name myFrontEnd --backend-pool-name myBackEndPool``` | ```aws elbv2 create-load-balancer --name my-load-balancer --type application --subnets subnet-0e3f5cac72EXAMPLE subnet-081ec835f3EXAMPLE``` |
| CDN | Azure CDN | Amazon CloudFront | Content delivery network | ```az cdn profile create --resource-group myRG --name myCDNProfile --sku Standard_Microsoft``` | ```aws cloudfront create-distribution --origin-domain-name mybucket.s3.amazonaws.com``` |

## Identity & Access Management

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Identity Management | Azure Active Directory | AWS IAM | User and access management | ```az ad user create --display-name "John Doe" --password P@ssw0rd1 --user-principal-name john@contoso.com``` | ```aws iam create-user --user-name john``` |
| Role-Based Access | Azure RBAC | IAM Roles | Permission management | ```az role assignment create --assignee john@contoso.com --role "Virtual Machine Contributor" --resource-group myRG``` | ```aws iam attach-user-policy --user-name john --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess``` |

## Container Services

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Container Registry | Azure Container Registry | Amazon ECR | Store container images | ```az acr create --resource-group myRG --name myContainerRegistry --sku Basic``` | ```aws ecr create-repository --repository-name my-repo``` |
| Orchestration | Azure Kubernetes Service (AKS) | Amazon EKS | Managed Kubernetes | ```az aks create --resource-group myRG --name myAKSCluster --node-count 2 --generate-ssh-keys``` | ```aws eks create-cluster --name my-cluster --role-arn arn:aws:iam::012345678910:role/eks-cluster-role --resources-vpc-config subnetIds=subnet-0a0bc0e57b126d27a,subnet-099de2538fc94e3f9,securityGroupIds=sg-0a9c85a3d911728d2``` |
| Serverless Containers | Azure Container Instances | AWS Fargate | Run containers without managing servers | ```az container create --resource-group myRG --name mycontainer --image mcr.microsoft.com/azuredocs/aci-helloworld --dns-name-label aci-demo --ports 80``` | ```aws ecs run-task --cluster default --task-definition my-task --launch-type FARGATE``` |

## Serverless Computing

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Functions | Azure Functions | AWS Lambda | Event-driven serverless code | ```func init MyFunctionProject --dotnet``` | ```aws lambda create-function --function-name my-function --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-role --handler lambda_function.handler --zip-file fileb://my-function.zip``` |
| Logic Apps | Azure Logic Apps | AWS Step Functions | Workflow orchestration | ```az logic workflow create --resource-group myRG --name myLogicApp --definition "path/to/definition.json"``` | ```aws stepfunctions create-state-machine --name "MyStateMachine" --definition "{\"Comment\":\"A Hello World example\",\"StartAt\":\"HelloWorld\",\"States\":{\"HelloWorld\":{\"Type\":\"Pass\",\"Result\":\"Hello World!\",\"End\":true}}}" --role-arn arn:aws:iam::123456789012:role/service-role/StepFunctions-MyStateMachine-role```  |

## AI/ML Services

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Machine Learning | Azure Machine Learning | Amazon SageMaker | Build and deploy ML models | ```az ml workspace create --workspace-name myworkspace --resource-group myRG``` | ```aws sagemaker create-notebook-instance --notebook-instance-name my-notebook --instance-type ml.t2.medium --role-arn arn:aws:iam::012345678901:role/service-role/AmazonSageMaker-ExecutionRole``` |
| Cognitive Services | Azure Cognitive Services | AWS AI Services | Pre-built AI capabilities | ```az cognitiveservices account create --name myaccount --resource-group myRG --kind TextAnalytics --sku S0 --location westus``` | ```aws comprehend detect-sentiment --text "I love AWS services" --language-code en``` |
| Bot Service | Azure Bot Service | Amazon Lex | Intelligent bots | ```az bot create --resource-group myRG --name myBot --kind registration``` | ```aws lex-models put-bot --name BookTrip --locale en-US --child-directed false --intent-summaries name=BookCar``` |

## Monitoring & Management

| Category | Azure | AWS | Purpose | Azure Example | AWS Example |
|----------|-------|-----|---------|--------------|-------------|
| Monitoring | Azure Monitor | Amazon CloudWatch | Performance monitoring | ```az monitor metrics alert create --name cpu-alert --resource-group myRG --condition "avg Percentage CPU > 70" --window-size 5m --action email``` | ```aws cloudwatch put-metric-alarm --alarm-name cpu-mon --comparison-operator GreaterThanThreshold --evaluation-periods 2 --metric-name CPUUtilization --namespace AWS/EC2 --period 120 --statistic Average --threshold 80 --alarm-actions arn:aws:sns:us-east-1:111122223333:my-topic``` |
| Infrastructure as Code | Azure Resource Manager | AWS CloudFormation | Template-based deployments | ```az deployment group create --resource-group myRG --template-file azuredeploy.json --parameters azuredeploy.parameters.json``` | ```aws cloudformation create-stack --stack-name my-stack --template-body file://template.yaml``` |
| DevOps | Azure DevOps | AWS CodePipeline | CI/CD pipelines | ```az devops project create --name MyProject --organization https://dev.azure.com/MyOrg/``` | ```aws codepipeline create-pipeline --pipeline-name MyPipeline --role-arn arn:aws:iam::123456789012:role/AWSCodePipelineServiceRole --artifact-store type=S3,location=codepipeline-bucket``` |
