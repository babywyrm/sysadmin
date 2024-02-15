How to decrypt Jenkins passwords from credentials.xml?

##
#
https://devops.stackexchange.com/questions/2191/how-to-decrypt-jenkins-passwords-from-credentials-xml
#
##


I've taken over the project where a lot of Jenkins credentials has passwords or passphrase strings which I need to know in order to progress with the project, unfortunately these weren't documented anywhere.

I've checked the credentials.xml file where these credentials are stored, but they're in not plain text, e.g.:

<passphrase>{AAAAAAAAAAAANzxft/rDzyt8mhxpn3O72dxvVqZksL5vBJ4jNKvAjAA=}</passphrase>

Note: I've changed it slightly for privacy reasons.

How can I decrypt its original password based on the string above?

    jenkinsencryption

Share
Improve this question
Follow
asked Sep 28, 2017 at 16:42
kenorb's user avatar
kenorb
7,8211212 gold badges3939 silver badges7777 bronze badges

    I am getting error with the proposed answer: println(hudson.util.Secret.decrypt("{{xxx/wwww+yyyy/zzzz=}}")) The + symbol is breaking the script. Any suggestion? – 
    Jay Bau
    Jun 14, 2019 at 17:35
    @JayBau Try with single brackets: "{...}", remove extra once. – 
    kenorb
    Jun 17, 2019 at 11:37 

    This is practically a duplicate of an SO question: stackoverflow.com/questions/37683143 (although technically it would only qualify as a duplicate if the linked question was asked on DevOps). – 
    Attila Csipak
    Mar 5, 2020 at 9:46

Add a comment
5 Answers
Sorted by:
122

Luckily there is a hudson.util.Secret.decrypt() function which can be used for this, so:

    In Jenkins, go to: /script page.

    Run the following command:

    println(hudson.util.Secret.decrypt("{XXX=}"))

    or:

    println(hudson.util.Secret.fromString("{XXX=}").getPlainText())

    where {XXX=} is your encrypted password. This will print the plain password.

    To do opposite, run:

    println(hudson.util.Secret.fromString("some_text").getEncryptedValue())

Source: gist at tuxfight3r/jenkins-decrypt.groovy.

Alternatively check the following scripts: tweksteen/jenkins-decrypt, menski/jenkins-decrypt.py.

For more details, check: Credentials storage in Jenkins.
Share
Improve this answer
Follow
edited Sep 28, 2017 at 22:15
answered Sep 28, 2017 at 16:42
kenorb's user avatar
kenorb
7,8211212 gold badges3939 silver badges7777 bronze badges

    3
    +1, for secret files that use SecretBytes class, you can see my answer. – 
    akostadinov
    Feb 19, 2020 at 11:13

Add a comment
36

Here is a short snippet you can just run from the jenkins script console, to dump all of your credentials to plain text.

com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{
  it.properties.each { prop, val ->
    if (prop == "secretBytes") {
      println(prop + "=>\n" + new String(com.cloudbees.plugins.credentials.SecretBytes.fromString("${val}").getPlainData()) + "\n")
    } else {
      println(prop + ' = "' + val + '"')
    }
  }
  println("-----------------------")
}

A more complicated version that lists for non-system credential providers:

import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.Credentials
import com.cloudbees.plugins.credentials.domains.Domain
import jenkins.model.Jenkins
def indent = { String text, int indentationCount ->
  def replacement = "\t" * indentationCount
  text.replaceAll("(?m)^", replacement)
}

Jenkins.get().allItems().collectMany{ CredentialsProvider.lookupStores(it).toList()}.unique().forEach { store ->
  Map<Domain, List<Credentials>> domainCreds = [:]
  store.domains.each { domainCreds.put(it, store.getCredentials(it))}
  if (domainCreds.collectMany{ it.value}.empty) {
    return
  }
  def shortenedClassName = store.getClass().name.substring(store.getClass().name.lastIndexOf(".") + 1)
  println "Credentials for store context: ${store.contextDisplayName}, of type $shortenedClassName"
  domainCreds.forEach { domain , creds ->
    println indent("Domain: ${domain.name}", 1)
    creds.each { cred ->
      cred.properties.each { prop, val ->
        println indent("$prop = \"$val\"", 2)
      }
      println indent("-----------------------", 2)
    }
  }
}

Share
Improve this answer
Follow
edited Apr 14, 2020 at 0:58
akostadinov's user avatar
akostadinov
15311 silver badge44 bronze badges
answered Jul 23, 2019 at 23:36
Magnus's user avatar
Magnus
46144 silver badges55 bronze badges

    How to modify this to get credentials from all domains, from all folders ? – 
    jmary
    Aug 14, 2019 at 9:47
    @jmary I have added another example – 
    Magnus
    Aug 15, 2019 at 0:58
    Great thanks :-) – 
    jmary
    Aug 16, 2019 at 9:00
    1
    if you want an even simpler oneliner: com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{println it.dump().replace(' ', '\n')} – 
    ymajoros
    Jan 17, 2020 at 10:36
    1
    I keep coming back to this again and again, thanks mate! – 
    Junaid
    May 24, 2023 at 7:46

Show 1 more comment
10

Based on Magnus' answer but as a simple one-liner with still readable output:

com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{println it.dump().replace(' ', '\n')}

Share
Improve this answer
Follow
edited Jul 13, 2022 at 8:37
community wiki

2 revs, 2 users 67%
ymajoros

    1
    Short and nice! – 
    akostadinov
    Feb 19, 2020 at 11:03

Add a comment
5

@kenorb example with hudson.util.Secret is good. Also answers listing all credentials are very useful (thanks @ymajoros for one-liner).

These do not handle secret files though where secretBytes are used and still an encrypted string is shown. In such case the SecretBytes class needs to be used. Assuming the file is UTF-8, one can do:

secret = "{....}"
new String(com.cloudbees.plugins.credentials.SecretBytes.fromString(secret).getPlainData())

HTH

Update: This is the full solution from my gits:

com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{
  it.properties.each { prop, val ->
    if (prop == "secretBytes") {
      println(prop + "=>\n" + new String(com.cloudbees.plugins.credentials.SecretBytes.fromString("${val}").getPlainData()) + "\n")
    } else {
      println(prop + ' = "' + val + '"')
    }
  }
  println("-----------------------")
}

Share
Improve this answer
Follow
edited Oct 11, 2021 at 15:01
answered Feb 19, 2020 at 11:08
akostadinov's user avatar
akostadinov
15311 silver badge44 bronze badges
Add a comment
4

For the record, The following snippet to be pasted into the console also does the job :

def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance,
    null,
    null
)

for(c in creds) {
  if(c instanceof com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey){
    println(String.format("id=%s  desc=%s key=%s\n", c.id, c.description, c.privateKeySource.getPrivateKeys()))
  }
  if (c instanceof com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl){
    println(String.format("id=%s  desc=%s user=%s pass=%s\n", c.id, c.description, c.username, c.password))
  }
}

Share
Improve this answer
Follow 
