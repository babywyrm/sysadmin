
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
