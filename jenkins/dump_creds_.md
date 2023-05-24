
Paste the below into the Jenkins script console:

```
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance,
    null,
    null
);
for (c in creds) {
     println( ( c.properties.privateKeySource ? "ID: " + c.id + ", UserName: " + c.username + ", Private Key: " + c.getPrivateKey() : ""))
}
for (c in creds) {
     println( ( c.properties.password ? "ID: " + c.id + ", UserName: " + c.username + ", Password: " + c.password : ""))
}
```



print-jenkins-secret-file-contents.groovy
```

import com.cloudbees.plugins.credentials.*;
import com.cloudbees.plugins.credentials.domains.Domain;
import org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl;

//
// modify fileName to match the filename of the secret(s) you want to print.
//  (ID would probably be more helpful... yay stack overflow copy pasta)
// alternatively comment out the filter [line 15] to dump all secret files.
// 
def fileName = "secrets.env"

SystemCredentialsProvider.getInstance().getCredentials().stream().
  filter { cred -> cred instanceof FileCredentialsImpl }.
  map { fileCred -> (FileCredentialsImpl) fileCred }.
  filter { fileCred -> fileName.equals( fileCred.getFileName() ) }.
  forEach { fileCred -> 
    String s = new String( fileCred.getSecretBytes().getPlainData() )
    println ""
    println "XXXXXX BEGIN a secret file with id=" + fileCred.getId() + " fileName=" + fileName + " XXXXXXXXXXXX"
    println s
    println ""
  }
  ```
  
  
##
##


```
node('<PICK A NODE TO RUN ON e.g. master>') {
    String text
    withCredentials([file(credentialsId: '<YOUR CREDENTIAL ID HERE>', variable: 'FILE')]) {
        text = readFile(FILE)
    }
    
    println "${text}"
 }



##
##


```
extract_jenkins_credentials.groovy
```
// To support more types of credentials, look up the credentials plugin code and write
// additional groovy to parse those credential types.
// 
// From Mohamed Saeed: https://medium.com/@eng.mohamed.m.saeed/show-all-credentials-value-in-jenkins-using-script-console-83784e95b857

def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance,
    null,
    null
);

for (c in creds) {
     println( ( c.properties.password ? "ID: " + c.id + ", UserName: " + c.username + ", Password: " + c.password : ""))
}
for (c in creds) {
     println( ( c.properties.privateKeySource ? "ID: " + c.id + ", UserName: " + c.username + ", Private Key: " + c.getPrivateKey() : ""))
}

// For decrypting a hash found in the web ui, if the above doesn't list the credential you want
// println(hudson.util.Secret.decrypt("{HASHxxxxx}"))




```
extract-credentials.groovy
```
// This Jenkins Groovy script extracts credentials in Jenkins and outputs them
// in a JSON format that can be digested by "Jenkins Configuration as Code".
// Just pass the output into a JSON to YAML converter.  You can run this
// through the Jenkins Script Console or similar.
//
// Thank you:
//  - https://github.com/tkrzeminski/jenkins-groovy-scripts/blob/master/show-all-credentials.groovy
//
// To conver to YAML `json2yaml | sed '/^[[:space:]]*$/d'`
//
import jenkins.model.*
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey
import com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl
import org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl
import org.jenkinsci.plugins.plaincredentials.StringCredentials
import com.microsoft.azure.util.AzureCredentials
import com.microsoftopentechnologies.windowsazurestorage.helper.AzureStorageAccount
import groovy.json.JsonOutput


// set Credentials domain name (null means is it global)
domainName = null

credentialsStore = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0]?.getStore()
domain = new Domain(domainName, null, Collections.<DomainSpecification>emptyList())

def credentials = []
credentialsStore?.getCredentials(domain).each{
  if (it instanceof UsernamePasswordCredentialsImpl)
    credentials += [
      usernamePassword: [
        scope: 'GLOBAL',
        id: it.id,
        username: it.username,
        password: it.password?.getPlainText(),
        description: it.description,
      ]
    ]
  else if (it instanceof BasicSSHUserPrivateKey) {
    data = [
      basicSSHUserPrivateKey: [
        scope: 'GLOBAL',
        id: it.id,
        username: it.username,
        passphrase: it.passphrase ? it.passphrase.getPlainText() : '',
        description: it.description,
        privateKeySource: [
          directEntry: [
            privateKey: it.privateKeySource?.getPrivateKey(),
          ]
        ]
      ]
    ]
    credentials += data
  } else if (it instanceof AWSCredentialsImpl)
    credentials += [
      aws: [
        scope: 'GLOBAL',
        id: it.id,
        accessKey: it.accessKey,
        secretKey: it.secretKey?.getPlainText(),
        description: it.description,
      ]
    ]
  else if (it instanceof AzureCredentials)
    credentials += [
      azure: [
        scope: 'GLOBAL',
        id: it.id,
        description: it.description,
        subscriptionId: it.subscriptionId,
        clientId: it.clientId,
        clientSecret: it.getPlainClientSecret(),
        azureEnvironmentName: it.azureEnvironmentName,
        tenant: it.tenant,

      ]
    ]
  else if (it instanceof StringCredentials)
    credentials += [
      string: [
        scope: 'GLOBAL',
        id: it.id,
        secret: it.secret?.getPlainText(),
        description: it.description,
      ]
    ]
  else if (it instanceof FileCredentialsImpl)
    credentials += [
      file: [
        scope: 'GLOBAL',
        id: it.id,
        fileName: it.fileName,
        secretBytes: it.secretBytes?.toString(),
        description: it.description,
      ]
    ]
  else if (it instanceof AzureStorageAccount)
    credentials += [
      azureStorageAccount: [
          scope: 'GLOBAL',
          blobEndpointURL: it.blobEndpointURL,
          description: it.description,
          id: it.id,
          storageAccountName: it.storageAccountName,
          storageKey: it.plainStorageKey,
      ]
    ]
  else
    credentials += [
      UNKNOWN: [
        id: it.id
      ]
    ]
}

def result = [
  credentials: [
    system: [
      domainCredentials: [
        [
          credentials: credentials
        ]
      ]
    ]
  ]
]
def json = JsonOutput.toJson(result)
println JsonOutput.prettyPrint(json)

return

