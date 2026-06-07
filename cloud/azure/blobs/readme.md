

##
#
https://medium.com/@Varma_Chekuri/introduction-to-azure-pentesting-2-de576dfb55b
#
https://github.com/Macmod/goblob
#
https://wizardcyber.com/azure-blob-storage-navigating-misconfiguration-risks/
#
https://rabobank.jobs/en/techblog/pentesting-azure-cloud-infrastructure/
#
https://github.com/redskycyber/Cloud-Security/blob/main/Azure-Security-Pentesting-Resources.md
#
https://github.com/cyberark/BlobHunter
#
##




Azure Blob Storage: Navigating Misconfiguration Risks
23 February 2024
by Abdallah Alhajeid
The Rise of Cloud Storage and Security Implications
As cloud hosting gains popularity, companies are increasingly turning to cloud vendors to host their data. Services such as Amazon S3 Buckets and Azure Blob Storage offer the convenience of storing data that is accessible by various users and services simultaneously, from anywhere in the world. This has revolutionized the way we think about data storage and accessibility, offering unprecedented levels of flexibility and scalability.

However, with this advancement comes a greater responsibility for security. One common vulnerability arises from the misconfiguration of storage services. Attackers often exploit these misconfigurations to search for and access publicly available files within the cloud storage service.

 

The Misconfiguration: A Closer Look
A typical scenario involves a company that wishes to grant access to its data through a third-party application or provide external access for collaboration purposes. During the initial setup of a storage account in Azure, the process includes configuring access controls for the storage containers.

Azure 1 

 

At this stage, administrators can inadvertently allow anonymous access to these containers. This is done through the configuration settings where the access level is defined:

Private Access: Only designated users and services have the rights to access the data, providing a high level of security.
Blob Access: The public cannot list the contents of the container, but anyone with the exact URL can access the blob, which could potentially expose sensitive data if URLs are leaked or guessed.
Container Access: This is the most permissive setting, allowing anyone to list all the contents of the container if they simply know its name and the associated storage account name.
azure 2

 

The Process and Risks of Enumeration:
When anonymous access is set to the container level, it becomes possible for an attacker to enumerate, or list, all the blobs within a container.

azure 3

They achieve this by first discovering the storage account name, which can often be guessed based on company naming conventions or through subdomain enumeration since Azure uses a predictable naming structure for storage accounts (e.g., [yourstorageaccount].blob.core.windows.net).

Once the attacker has the storage account name, they can attempt to list containers and their contents. If they find a container with anonymous access enabled, they can proceed to access the data stored within—whether it be sensitive files, backups, or other critical information.

Example Scenario: Two containers, ‘test’ and ‘test2,’ are created, potentially exposing files like ‘azure-dev-backup.db.txt’ and ‘test.txt’ to unauthorized access.

azure 4

 

The Attack Explained: Exploiting Azure Blob Storage Misconfiguration
Understanding the Vulnerability
In scenarios where attackers operate with limited prior system knowledge—a method known as ‘black box’ hacking—they aim to uncover two key pieces of information to exploit Azure Blob Storage: the names of the container and its corresponding storage account. Azure’s methodology of allocating distinct subdomains for each storage account, typically in the format

‘ [chosenaccountname].blob.core.windows.net ‘

can become a security loophole. Companies often select storage account names that mirror their corporate domain, potentially making it more predictable and hence, more susceptible to infiltration by cyber attackers.

The Enumeration Process
Storage Account Discovery: Attackers begin by identifying potential storage account names, often using automated tools to generate permutations based on the company’s known domain name.
Container Name Guessing: Once the storage account is pinpointed, the attacker proceeds to guess or enumerate container names, which are often not as carefully guarded and may follow a generic naming convention, such as ‘attachments’, ‘images’, or ‘backups’.
Listing and Accessing Blobs: With both the storage account and container names, the attacker can list all blobs within the container. If the blobs are stored with anonymous access enabled, the attacker can access any or all of them without needing further authentication.
The Tool for Enumeration
To demonstrate this vulnerability, I have developed a tool that simplifies the process:

Detecting Storage Accounts: The tool scans for storage accounts related to a given name, in this case, ‘acme’.
azure 5

2. Scanning for Containers: It then scans the detected storage account, such as ‘acmetest’, which is identified as number 3 in the tool’s output, to list all containers that may be publicly accessible.

azure 6

 

Mitigation Strategies
To prevent such security breaches, companies must adopt stringent configuration practices:

Avoid granting anonymous access unless absolutely necessary for public data.
If public access is required, use blob-level access to prevent listing and ensure URLs are not easily guessable.
Implement strict naming conventions for containers that do not directly relate to the company or the type of data stored, making them difficult for attackers to predict.
Regularly audit storage accounts and container access policies to ensure they align with security best practices.
Employ additional layers of security such as Azure’s Advanced Threat Protection to detect anomalous access patterns.
By understanding the risks associated with cloud storage misconfiguration and taking proactive steps to secure assets, companies can leverage the benefits of the cloud while mitigating potential threats to their data.

 
