##
#
https://gist.github.com/thesaravanakumar/884752979726713e2ee34e026539229e
#
https://www.tinfoilcipher.co.uk/2020/05/26/terraform-hacks-running-in-line-scripts/
#
https://spacelift.io/blog/terraform-commands-cheat-sheet
#
##


```
provider local {}

provider null {}

variable "script_location" {
    type        = string
    description = "script location"
    default     = "watcher.sh"
}

variable "file_watch" {
    type        = string
    description = "script location"
    default     = "watching.conf"
}

resource "null_resource" "run_script" {
    #--Trigger should apply only when script changes
    triggers = {
        script_hash = filemd5(var.file_watch)
    }
    
    #--Run script when the configuration file has changed
    provisioner "local-exec" {
        command = "bash ./${var.script_location}"
    }
}
```

<img width="200" align="right" src="https://user-images.githubusercontent.com/59575502/201074420-95aff0ef-9660-464c-82da-c7daeb063a95.png">

## Terraform Commands 
There are a couple of commands to check the Terraform’s built-in command-line documentation: 

- ```terraform```
- ```terraform -h```
- ```terraform --help```

The resulting help page will have the main commands at the top, followed by the less common or more complex commands below. 

<div align="center">
<img width="600" src="https://user-images.githubusercontent.com/59575502/201073861-56229fc4-e738-40b5-89ef-5d7d7bf7f0a8.jpeg">
</div>

We can also enter the terraform command and then a subcommand with -h or --help to pull up a list of commands that are specific to that subcommand.  

### Important Terraform commands: 

- ```fmt``` - When we finish our Terraform configuration, we can make sure that everything is formatted correctly.
- ```init``` - The init command looks at your configuration files and determines which providers and modules it needs to pull down from the registry to allow your configuration to work properly. 
- ```validate``` - Validation will catch syntax errors, version errors, and other issues.
- ```plan``` - Next, it’s always a good idea to do a dry run of your plan to see what it’s actually going to do.
- ```apply``` - This is the command that deploys or applies your configuration to a provider. 
- ```destroy``` - The destroy command, obviously, will destroy your infrastructure
- ```output``` -  The output command to make those defined outputs to display certain information.
- ```show``` - The show command shows the current state of a saved plan.
- ```state``` - Another good way to check your work is to use the state command. 
- ```version``` - We will use the version command quite a bit to check our Terraform version,

### Logging in terraform
The environment variableTF_LOG defines the log level. Valid log levels are (in order of decreasing verbosity): TRACE, DEBUG, INFO, WARN or ERROR.

- Bash 
    - export TF_LOG="DEBUG"
    - export TF_LOG_PATH="tmp/terraform.log"
- PowerShell
    - $env:TF_LOG="DEBUG"
    - $env:TF_LOG_PATH="C:\tmp\terraform.log"

To set them permanently, you can add these environment variables to your .profile, .bashrc, PowerShell profile (if it exists, the path is stored in $profile environment variable) file, or the appropriate profile for your chosen shell.

### Terraform CLI tricks 

- ```terraform -install-autocomplete``` #Setup tab auto- completion, requires logging back in 

### Format and Validate Terraform code

- ```terraform fmt``` - format code per HCL canonical standard 
- ```terraform validate``` - validate code for syntax 
- ```terraform validate -backend=false``` - validate code skip backend validation 

### Initialize your Terraform working directory

- ```terraform init``` - initialize directory, pull down providers 
- ```terraform init -get-plugins=false``` - initialize directory, do not download plugins 
- ```terraform init -verify-plugins=false``` - initialize directory, do not verify plugins for Hashicorp signature 

### Plan, Deploy and Cleanup Infrastructure

- ```terraform show``` - to inspect current state.
- ```terraform apply --auto-approve``` - apply changes without being prompted to enter “yes” 
- ```terraform destroy --auto-approve``` - destroy/cleanup deployment without being prompted for “yes” 
- ```terraform plan -out plan.out``` - output the deployment plan to plan.out 
- ```terraform apply plan.out``` - use the plan.out plan file to deploy infrastructure 
- ```terraform plan -destroy``` - outputs a destroy plan 
- ```terraform apply -target=aws\_instance.my\_ec2``` - only apply/deploy changes to the targeted resource 
- ```terraform apply -var my\_region\_variable=us-east-1``` - pass a variable via command-line while applying a configuration 
- ```terraform apply -lock=true``` - lock the state file so it can’t be modified by any other Terraform apply or modification action(possible only where backend allows locking) 
- ```terraform apply refresh=false``` - do not reconcile state file with real-world resources(helpful with large complex deployments for saving deployment time) 
- ```terraform apply --parallelism=5``` - number of simultaneous resource operations 
- ```terraform refresh``` - reconcile the state in Terraform state file with real-world resources 
- ```terraform providers``` - get information about providers used in current configuration 

### Terraform Workspaces

- ```terraform workspace new mynewworkspace``` - create a new workspace 
- ```terraform workspace select default``` - change to the selected workspace 
- ```terraform workspace list``` - list out all workspaces
- ```terraform workspace``` - shows workspaces

### Terraform State Manipulation

- ```terraform.tfstate.backup``` - stores previous state
- ```terraform.tfstate``` - stores current state
- ```terraform state show [options] ADDRESS``` - shows the attributes of a single resource
- ```terraform state show aws\_instance.my\_ec2``` - show details stored in Terraform state for the resource 
- ```terraform state pull > terraform.tfstate``` - download and output terraform state to a file 
- ```terraform state mv aws\_iam\_role.my\_ssm\_role module.custom\_module``` - move a resource tracked via state to different module 
- ```terraform state replace-provider hashicorp/aws registry.custom.com/aws``` - replace an existing provider with another 
- ```terraform state list``` - list out all the resources tracked via the current state file 
- ```terraform state rm  aws\_instance.myinstace``` - unmanage a resource, delete it from Terraform state file 

### Terraform Import And Outputs

- ```terraform import aws\_instance.new\_ec2\_instance i- abcd1234``` - import EC2 instance with id i-abcd1234 into the Terraform resource named “new\_ec2\_instance” of type “aws\_instance” 
- ```terraform import 'aws\_instance.new\_ec2\_instance[0]' i- abcd1234``` - same as above, imports a real-world resource into an instance of Terraform resource 
- ```terraform output``` - list all outputs as stated in code 
- ```terraform output instance\_public\_ip``` - list out a specific declared output 
- ```terraform output -json``` - list all outputs in JSON format 

### Terraform Miscelleneous commands

- ```terraform version``` - display Terraform binary version, also warns if version is old 
- ```terraform get -update=true``` - download and update modules in the “root” module. 

### Terraform Console(Test out Terraform interpolations)

- ```echo 'join(",",["foo","bar"])' | terraform console``` - echo an expression into terraform console and see its expected result as output 
- ```echo '1 + 5' | terraform console``` - Terraform console also has an interactive CLI just enter “terraform console” 
- ```echo "aws\_instance.my\_ec2.public\_ip" | terraform console``` - display the Public IP against the “my\_ec2” Terraform resource as seen in the Terraform state file 

### Terraform Graph(Dependency Graphing)

- ```terraform graph | dot -Tpng > graph.png``` - produce a PNG diagrams showing relationship and dependencies between Terraform resource in your configuration/code 

### Terraform Taint/Untaint(mark/unmark resource for recreation - > delete and then recreate)

- ```terraform taint aws\_instance.my\_ec2``` - taints resource to be recreated on next apply 
- ```terraform untaint aws\_instance.my\_ec2``` - Remove taint from a resource 
- ```terraform force-unlock LOCK\_ID``` - forcefully unlock a locked state file, LOCK\_ID provided when locking the State file beforehand 

### Terraform Cloud 

- ```terraform login``` - obtain and save API token for Terraform cloud 
- ```terraform logout``` - Log out of Terraform Cloud, defaults to hostname app.terraform.io 

### Terraform variables precedence (low to high)

- terraform.tfvars
- terraform.tfvars.json
- *.auto.tfvars, *.auto.tfvars.json
- -var, -var-file
