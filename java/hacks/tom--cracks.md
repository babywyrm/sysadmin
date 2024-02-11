
https://docs.oracle.com/cd/F56930_01/docker_atp_install_guides/admin_console_deployment_guide_for_tomee/Content/Docker/Admin%20Console%20Deployment%20for%20TomEE/Encrypting%20Tomcat%20Passwords.htm

https://gist.github.com/gquere/4302ebb67274d4112e4e63277ca9faf9

##
##


server.xml:
```xml
<Realm className="org.apache.catalina.realm.LockOutRealm">
    <Realm className="org.apache.catalina.realm.UserDatabaseRealm" resourceName="UserDatabase" digest="sha-256" />
</Realm>
```

tomcat-users.xml (test values from https://www.techpaste.com/2013/05/enable-password-encryption-policy-tomcat-7/):
```xml
<tomcat-users xmlns="http://tomcat.apache.org/xml"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd" version="1.0">
    <user username="manager" password="371c8e07f4d7c0ae8b352e675ad67ee3c4e44154a50be700e42c66ed3741c3f4$1$e0f79e487e8c443aff9777d825ffd95d8d29e5b1c45b7a041b3c37ecb1418faa"/>
</tomcat-users>
```

Above format is:
```
salt$iteration_count$hash
```
Where salt and hash are hex-encoded.

SHA256(salt + pass) corresponds to John's dynamic_61 mode. Looking at the doc it appears that the salt is text, so for our hex value it has to be prepended with ```HEX$```
```
manager:$dynamic_61$e0f79e487e8c443aff9777d825ffd95d8d29e5b1c45b7a041b3c37ecb1418faa$HEX$371c8e07f4d7c0ae8b352e675ad67ee3c4e44154a50be700e42c66ed3741c3f4
```

```
john tomcat_test_hash.txt --format=dynamic_61 --wordlist=wordlist 
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic_61 [sha256($s.$p) 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 48 needed for performance.
mysecret_password (manager)     
```

Happy cracking!



You are here: Encrypting tomcat-users.xml Passwords




Encrypting tomcat-users.xml Passwords
It’s a good practice to encrypt the user passwords in tomcat-users.xml. Following are sample procedures/steps to encrypt the corresponding passwords.

Note: The following configuration is just an example of hashing the passwords using 'SHA-512' algorithm. This should be changed depending on the standards prescribed by individual companies.

To Hash the user password in tomcat-users.xml:

Navigate to the bin folder in tomee home directory.

Open digest.sh for Linux.

Generate the hashed string for the user password by providing the user password as input.

For Using the SHA-256 algorithm:

For Linux env:
./digest.sh -a sha-256 -h org.apache.catalina.realm.MessageDigestCredentialHandler password (this password is the actual user password)

For Using the SHA-512 algorithm:

For Linux env:
./digest.sh -a sha-512 -h org.apache.catalina.realm.MessageDigestCredentialHandler password (this password is the actual user password)

For Using the SHA-md5 algorithm:

For Linux env:
./digest.sh -a md5 -h org.apache.catalina.realm.MessageDigestCredentialHandler password (this password is the actual user password)

Once the hashed string is generated with any of the above algorithms, change the configurations in the server.xml file

<Realm className="org.apache.catalina.realm.LockOutRealm">

```
```
<!-- This Realm uses the UserDatabase configured in the global JNDIresources under the key "UserDatabase". Any edits that are performed against this UserDatabase are immediately available for use by Realm.

<Realm className="org.apache.catalina.realm.UserDatabaseRealm" resourceName="UserDatabase">
<CredentialHandler className="org.apache.catalina.realm.MessageDigestCredentialHandler" algorithm="SHA-512" />
</Realm>
</Realm>
The algorithm selected for hashing the given password should the same as the algorithm mentioned in the server.xml file.

Finally, the generated hashed password should be updated in the tomcat-users.xml file

Example: <user username="qatester" password="c732f45c5877232dbbc992b464f3fcc413310ace9cb0fce543beeb4d462d5801" roles="AC_ADMIN" />>



 
    <!-- An Engine represents the entry point (within Catalina) that processes
         every request.  The Engine implementation for Tomcat stand alone
         analyzes the HTTP headers included with the request, and passes them
         on to the appropriate Host (virtual host).
         Documentation at /docs/config/engine.html -->

    <!-- You should set jvmRoute to support load-balancing via AJP ie :
    <Engine name="Catalina" defaultHost="localhost" jvmRoute="jvm1">
    -->
    <Engine name="Catalina" defaultHost="localhost">

      <!--For clustering, please take a look at documentation at:
          /docs/cluster-howto.html  (simple how to)
          /docs/config/cluster.html (reference documentation) -->
      <!--
      <Cluster className="org.apache.catalina.ha.tcp.SimpleTcpCluster"/>
      -->

      <!-- Use the LockOutRealm to prevent attempts to guess user passwords
           via a brute-force attack -->
      <Realm className="org.apache.catalina.realm.LockOutRealm">
        <!-- This Realm uses the UserDatabase configured in the global JNDI
             resources under the key "UserDatabase".  Any edits
             that are performed against this UserDatabase are immediately
             available for use by the Realm.  -->
      <Realm className="org.apache.catalina.realm.UserDatabaseRealm" resourceName="UserDatabase">
             <CredentialHandler className="org.apache.catalina.realm.MessageDigestCredentialHandler" algorithm="SHA-256" />
      </Realm>
      </Realm>

      <Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">

        <!-- SingleSignOn valve, share authentication between web applications
             Documentation at: /docs/config/valve.html -->
        <!--
        <Valve className="org.apache.catalina.authenticator.SingleSignOn" />
        -->

        <!-- Access log processes all example.
             Documentation at: /docs/config/valve.html
             Note: The pattern used is equivalent to using pattern="common" -->
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />

      </Host>
    </Engine>
  </Service>
</Server>

 
