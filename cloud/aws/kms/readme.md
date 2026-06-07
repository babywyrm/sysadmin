The individual parts of AWS KMS are:

# master key
# encryptor key (encrypted and unencrypted forms)
# app's private key


Note: the "encryptor" is a key used to encrypt our private key

Here is a simple example to demonstrate the workflow:

Create a master key in KMS (how you do this is up to you: SDK, CLI, Console)
Locally (via the AWS cli tool or maybe even via a CI) call GenerateDataKey
When making this call: pass the name of the "master key" in KMS to use
This results in a temp key B (in both unencrypted and encrypted form) being provided
We can now encrypt key A using the unencrypted B key
We can discard both the unencrypted A and B keys (as we now have encrypted versions)
We can bake the encrypted keys (A and B) into our application (as they're encrypted)
When our app needs to use key A, it needs to decrypt it
Our app uses KMS to decrypt the B key
Our app then uses the resulting unencrypted B key to decrypt our A encrypted key
Further comments from Steven Jack:

Imagine we have a Jenkins CI job that runs every week.
It has IAM perms to call GenerateDataKey for a specific master key.

Each week it generates a new random hash for the DB password,
get’s the temp encryption key,
encrypts it and pushes both the parts needed into a Kubernetes secrets store.

Once that’s done we simply re-deploy the containers, done.

The app has decrypt perms for that master key and on boot
give the param it has from the secrets store and get back
the unencrypted key and decrypt its secret, then uses it.

@Integralist
Author
Integralist commented on May 10, 2016
Here are more thoughts from Steven Jack on some uses of AWS KMS with Kubernetes and AWS Lambda...

Been thinking about the client certs for the kubernetes cluster and how best to provision them, the best practices state:

You should setup your own PKI infra and create your own CA.
Each of the master (Controller, nodes that do scheduling etc) nodes have a client cert that has the internal virtual IP of the ‘api server’ and load balancer DNS as the SAN fields on them.
Each of the worker/minion nodes needs to have an individual client cert (So it’s easy to work out who’s making the calls and seems to be best practice for each to have their own rather than a shared cert) that has either the ec2 DNS name in it’s SAN, or a private hosted zone DNS name like ‘i-4398djed9e.kubernetes.node.local` for instance - either way they need a unique identifiable address.
Now my idea to accomplish this is as follows, wanted to see if anyone could see any gaping security issues in my potential solution:

Generate the CA and push it up into KMS.
have a lambda function that is the only service in the AWS account (Apart form the user that pushed up the CA) that can use the master key to decrypt the CA, it takes a set of hostnames/DNS names and generates a client cert which is then encrypted and stored in s3 in a unique path with an auto expiring link that is added to the resource requesting it as a tag. For example:
We have the worker ASG for kubernetes, when we get a notification that a new instance is booting it fires off the above lambda function which looks the instance up and grabs it’s DNS name, generates a client cert, encrypts it and stores it in S3 then applys a tag to the instance with the s3 link so when it boots up, it looks for the tag then pulls that cert in from s3 and decrypts it.

I think that should be fine as even if someone somehow got hold of the s3 link (Would have like a 5/10 min expiry) they’d still only have the encrypted cert.

I’ve already done a proof of concept to generate the certs in a lambda function, all of which is in memory and not storing either the CA private key or generated keys on disk (not sure of the security model with lambda and reuse etc)




```
# Define your AWS_KMS_ARN, KMS_REGION, KMS_AWS_ACCESS_KEY_ID, KMS_AWS_SECRET_ACCESS_KEY someplace
import base64
import boto3
from Crypto.Cipher import AES

class AwsKms(object):

    def __init__(self):
        self.key_id = AWS_KMS_ARN
        self.client = boto3.client('kms',
                                   region_name=KMS_REGION,
                                   aws_access_key_id=KMS_AWS_ACCESS_KEY_ID,
                                   aws_secret_access_key=KMS_AWS_SECRET_ACCESS_KEY)

    def generate_data_key(self, key_spec='AES_256'):
        """returns plaintext and encrypted key.
           Store the encrypted key / Use the plaintext key and promptly discard
        """
        response = self.client.generate_data_key(KeyId=self.key_id, KeySpec=key_spec)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return base64.b64encode(response['CiphertextBlob'])
        # if you cannot generate the symmetric key itself, something is wrong with your
        # credentials...bail out
        raise Exception('Error while generating data key: {0}'.format(response))

    def get_plaintext_symmetric_key(self, cipherkey):
        response = self.client.decrypt(CiphertextBlob=base64.b64decode(cipherkey))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return response['Plaintext']

    def encrypt(self, plaintext, cipherkey):
        symmetric_key = self.get_plaintext_symmetric_key(cipherkey)
        if not symmetric_key:
            # either log something or raise an exception here...
            return
        return base64.b64encode(AES.new(symmetric_key, AES.MODE_CFB).encrypt(plaintext))

    def decrypt(self, ciphertext, cipherkey):
        symmetric_key = self.get_plaintext_symmetric_key(cipherkey)
        if not symmetric_key:
            # either log something or raise an exception here...
            return
        return AES.new(symmetric_key, AES.MODE_CFB).decrypt(base64.b64decode(ciphertext))
```
