

# Getting Started with Salt Cloud and Microsoft Azure (2025 Guide)

Welcome to the modern guide for integrating Salt Cloud with Microsoft Azure. This document will walk you through using Salt Cloud to provision and manage virtual machines and other resources on Azure's powerful cloud platform.

This guide focuses exclusively on the current **Azure Resource Manager (ARM)** model, which is the standard for all modern Azure deployments.

### A Note on Legacy Azure Models
The original Salt Cloud Azure driver (`azure`) was built for the classic Azure Service Manager (ASM) deployment model. ASM has been superseded by ARM. This guide uses the modern `azurearm` driver, which is the recommended and standard way to interact with Azure.

---

## 1. Prerequisites

Before you begin, you will need the following:

*   **An active Microsoft Azure Subscription:** If you don't have one, you can [create a free account](https://azure.microsoft.com/en-us/free/).
*   **A running Salt Master:** It is recommended to use a recent version of Salt (e.g., 3006 or newer).
*   **Azure CLI:** The Azure Command-Line Interface is the easiest way to configure authentication. [Install the Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) on your Salt Master or local workstation.
*   **Required Python Libraries:** The `azurearm` driver requires specific Python libraries. You can typically install them with pip:
    ```bash
    pip install "apache-libcloud[azure]"
    ```

## 2. Authentication: Creating a Service Principal

Modern applications authenticate with Azure using a **Service Principal**, which is an identity for your application (in this case, Salt Cloud) to securely access resources. The easiest way to create one is with the Azure CLI.

1.  Log in to your Azure account:
    ```bash
    az login
    ```

2.  Create a Service Principal. This command will create the identity and grant it the "Contributor" role over your entire subscription, allowing it to manage resources.
    ```bash
    az ad sp create-for-rbac --name SaltCloudProvider --role Contributor
    ```

3.  The command will output a JSON block. **Save this information securely**, as you will need it for the Salt Cloud configuration.

    ```json
    {
      "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "displayName": "SaltCloudProvider",
      "password": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "tenant": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
    ```

    *   `appId`: This is your **Client ID**.
    *   `password`: This is your **Client Secret**.
    *   `tenant`: This is your **Tenant ID**.

## 3. Salt Cloud Provider Configuration

Next, you need to tell Salt Cloud how to connect to your Azure account. Create a provider configuration file at `/etc/salt/cloud.providers.d/azure.conf`.

Populate it with the credentials from the previous step and your Azure Subscription ID.

```yaml
# /etc/salt/cloud.providers.d/azure.conf

my-azure-arm-config:
  driver: azurearm
  # Find this in the Azure Portal or with `az account show`
  subscription_id: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
  # The 'appId' from the previous step
  client_id: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
  # The 'password' from the previous step
  client_secret: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
  # The 'tenant' from the previous step
  tenant: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Set up the location of the salt master
minion:
  master: your-salt-master.example.com
```

## 4. Creating a Cloud Profile

A profile is a template for the virtual machines you want to create. Create a profile configuration file at `/etc/salt/cloud.profiles.d/azure-vms.conf`.

This example defines a small Ubuntu 22.04 LTS server in the "East US" region.

```yaml
# /etc/salt/cloud.profiles.d/azure-vms.conf

azure-ubuntu22-lts:
  provider: my-azure-arm-config
  size: Standard_B1s
  image: 'Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest'
  location: 'East US'
  resource_group: 'SaltManagedVMs'
  network: 'SaltVNet'
  subnet: 'default'
  ssh_username: 'azureuser'
  # For better security, use ssh_key_file instead of a password
  # ssh_key_file: /etc/salt/keys/azure_id_rsa
  ssh_password: 'AVeryComplexP@ssw0rd!2025'
  # Optional: Assign a public IP address
  public_ip: True
```

### Profile Options Explained

*   **`provider`**: The name of the provider configuration you created in `azure.conf`.
*   **`size`**: The virtual machine size. You can list available sizes with `salt-cloud --list-sizes my-azure-arm-config`.
*   **`image`**: The image URN (Uniform Resource Name). You can find images with `salt-cloud --list-images my-azure-arm-config`.
*   **`location`**: The Azure region for deployment. List available locations with `salt-cloud --list-locations my-azure-arm-config`.
*   **`resource_group`**: The container that holds related resources for an Azure solution. Salt Cloud will create it if it doesn't exist.
*   **`network`** and **`subnet`**: The virtual network and subnet for the VM. Salt Cloud will create these if they don't exist within the same resource group.
*   **`ssh_username`** and **`ssh_password` / `ssh_key_file`**: Credentials used by Salt Cloud to bootstrap the Salt Minion onto the new VM. **Using an SSH key is strongly recommended for production environments.**

## 5. Core Actions: Managing Virtual Machines

With your provider and profile configured, you can now manage VMs with simple commands.

### Create a Virtual Machine

This command creates a new VM named `web-server-01` using the `azure-ubuntu22-lts` profile.

```bash
salt-cloud -p azure-ubuntu22-lts web-server-01
```

Salt Cloud will connect to Azure, provision all the necessary resources (resource group, networking, storage, VM), install the Salt Minion, and automatically accept the new minion's key on the Salt Master.

### Verify Connectivity

Once the instance is ready, you can verify that the Salt Master can communicate with it:

```bash
salt 'web-server-01' test.ping
```

### Querying Instances

You can view basic information about your cloud instances or get a full data dump.

```bash
# List all instances managed by Salt Cloud
salt-cloud -Q

# Get full details for a specific instance
salt-cloud -a show_instance web-server-01
```

### Destroying a Virtual Machine

To delete a VM and its associated resources, use the `-d` or `--destroy` flag.

```bash
salt-cloud -d web-server-01
```

By default, this command deletes the VM, its network interface, and its public IP address. The OS disk, VNet, and resource group will remain.

#### **Complete Cleanup**

To destroy the VM and its entire resource group (including VNet, storage, and any other resources), you can set the `destroy_resource_group` property to `True` in your profile or pass it on the command line.

```bash
# This is a destructive action that will delete everything in the resource group!
salt-cloud -d web-server-01 -y --set-destroy-param=destroy_resource_group=True
```

## 6. Advanced Resource Management

While Salt Cloud's primary strength is VM provisioning, the `azurearm` driver can also manage other Azure resources directly using functions.

### Example: Managing Resource Groups

You can list, create, or delete resource groups without creating a VM.

```bash
# List all resource groups in your subscription
salt-cloud -f list_resource_groups my-azure-arm-config

# Create a new, empty resource group
salt-cloud -f resource_group_create my-azure-arm-config \
  name=NewEmptyRG location='East US'

# Delete a resource group
salt-cloud -f resource_group_delete my-azure-arm-config name=NewEmptyRG
```

The `azurearm` driver contains many other functions for managing storage, networks, and more. For a complete list of available functions and their parameters, please refer to the [official Salt Cloud azurearm module documentation](https://docs.saltproject.io/en/latest/ref/clouds/all/salt.cloud.clouds.azurearm.html).
