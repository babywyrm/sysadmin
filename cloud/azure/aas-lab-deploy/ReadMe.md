<h1 align="center">
  <br>
    <a href="https://github.com/aas-n/deployAzureADLab"><img src="https://i.ibb.co/Jt69TPV/azure.png" alt="image-azure-TW-1"></a>
  <br>
  <br>
</h1>

<p align="center">
  <a href="https://twitter.com/lydericlefebvre">
    <img src="https://img.shields.io/badge/Twitter-%40lydericlefebvre-blue.svg">
  </a>
</p>


### Index
| Title        | Description   |
| ------------- |:-------------|
| [About](#about)  | Brief Description about the script |
| [Installation](#installation)  | Installation and Requirements |
| [Usage](#Usage)  | How to use this script |
| [Acknowlegments](#acknowlegments)  | Acknowlegments |

### About
This is a little script based on AutomatedLab to deploy heterogenous Active Directory lab on Azure with emulation of users behaviors

### Installation
To deploy on Azure, you have to have an Azure account.
* `You can have a free one, but limited to 4 Core (OK to deploy up to 4 VMs).`
* `https://azure.microsoft.com/en-us/free/`

Install automatedlab (msi setup)
* `https://github.com/AutomatedLab/AutomatedLab/releases`

Install Azure Powershell
* `Install-Module -Name Az -AllowClobber -Scope CurrentUser
 `

### Usage
Simply start the script:
```bash
.\deploy.ps1
```

### Acknowlegments  
Spraykatz uses slighlty modified parts of the following projects:
* [AutomatedLab](https://github.com/AutomatedLab/AutomatedLab)

#
Written by [Lydéric Lefebvre](https://twitter.com/lydericlefebvre)
