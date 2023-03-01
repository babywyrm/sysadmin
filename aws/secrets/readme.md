Secretmanager and Key Management Service. (KMS) in AWS.

##
#
https://gist.github.com/rshettynj/8b446cc70d5bcb52b9d6c36ba97aa5ce
#
##

1. What is "aws secretmanager" ?
AWS Secret Manager is a managed service by AWS to store and manage the "secrets". Secrets meaning it can be any random string that 
you consider that it should be "secret". Meaning not available to view for everyone. example: list of SSN ids is a secret.
{ "sam": "123-02-2000", "mike": "123-38-3939", "jane": "132-93-2939" }
It should be visible or available to the intended users only.

As such, "encrypting" and "storing the encrypted data" securely are challenging/complicated steps. 
Secretmanager service "hides" all these complexicity with this service. All we need to do is "create" and "get" the secrets 
without worrying how it is done.
Secretmanager is also directly integrated with many AWS services for quick retrieveal of the secrets.

secretmanager works in conjunction with AWS KMS (key Management Service.)

AWS KMS is service used for "creating" the customer master key. (CMK).  This is the key that can be used for encrypting the data.
However KMS does not handle storing/retrieving the user data. It only provides the "key" and stores only that "key", nothing else.

So managing the user data and related complexicity falls on someone. That someone is "secret manager".

So in a nutshell, secretmanager uses the specified KMS Key to generate the encrypted data and stores it. It will then refer back to
KMS key again when data needs to be decrypted.

However it involves few steps. Internal of the secretmanager to KMS works like this..

1. You create a KMS id. (say a CMK custom key.) You get a Keyid (ARN of the key.). This is also called as master key.
master key itself can be used to encrypt data but generally it is not done as it is not best practice and only 4 KB data can be 
encrypted.  Also one CMK can encrypt multiple data, no limits there.  Again not a good practice.

2. When secret manager contacts the KMS, it creates a "data key" using the KMS API calls. "Data key" as a best practice should be 
created for every data being encrypted. Data key consists of two parts.  (think of data key as a intermediate or your data specific
key)

a. encrypted data key
b. plaintext data key

secretmanager then "adds" the plaintext data key to your data to generate encrypted data. (what we now call secret.)

"customer data" +  plaintext data key (b)  =  final secret (c)

3. secretmanager now "deletes" the "plaintext data key".

4. secretmanager now "stores" the "final secret" in a "envelope".  This is called "envelope encryption".
Outer cover of the envelope is the "encrypted data key (a)" and inner content is the "final secret (c)".

"final secret (c)" + "encrypted data key(a)"  -> secret is now ready to store in secret manager storage area.

We can also think of "encrypted data key(a)" as a "metadata" part of the secret.

In above steps, you will notice few things..

a. KMS CMK id never leaves the KMS boundary.
b. Data key is never stored in KMS. It is stored as part of the customer data in secretmaneger. KMS has nothing to do with data key
or customer data.
c. One KMS CMK id can be used by multiple data keys. One KMS CMK Id can encrypt multiple customer data sets. However these 
scenarios are not encouraged. Use one data key for one data set and ideally one KMS key.

5. When data needs to be decrypted, secretmanager contacts KMS CMK to "decrypt" the "encrypted data key(a)" 
(metadata a.k.a, outer envelope).

6. secretmanager decrypts the user data using decrypted data key and then decrypts the data to get it in plaintext.

So steps 2/3/4/5/6 are transparent to admins and handled by secretmanager. If not using secretmanager, you will have to use the 
api calls (to kms) and appropriate encryption libraries (openssl) to encrypt and find a place to store the secrets.

Examples:

Lambda function to "create" and "get" secrets.

"Create" - creates the secret and stores in secretmanager using above steps explained. 
You create KMS CMK in advance and provide permissions for KMS CMK access and secretmanager access to the lambda role.

"get" - gets the secret in plaintext using above steps explained.

See attached gistfile2.txt

Command line to "get" secrets.

aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-1:55xxxx43:secret:ssxxx-brIskQ --region us-east-1
{
    "Name": "sxxxetty",
    "VersionId": "99689eea-106b-4f7b-b291-2245dd829ff8",
    "SecretString": "{\"rosty\":\"1521230001\",\"soria\":\"1521230002\",\"adtty\":\"1521230003\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1589911934.824,
    "ARN": "arn:aws:secretsmanager:us-east-1:559xxxx943:secret:ssy-brIskQ"
}



gistfile2.txt
```
import json
import boto3

client = boto3.client('secretsmanager')

kms_key_id = '72e68de2-1e10-4aa0-a6ad-a3xxxxxx9'

def create_secret():
    try:
        response = client.create_secret(
        Name='ssn001',
        Description='testing secret manager',
        KmsKeyId=kms_key_id,
        #if you do not want to show the string below, get from SSM (parameter store secureString.)
        SecretString='{ "shan": "0001", "neill": "0002", "tom": "0003" }',
        Tags=[
            {
                'Key': 'purpose',
                'Value': 'testing'
            },
        ]
        )
        return(response)
    except Exception as e: print(e)

secretid ='arn:aws:secretsmanager:us-east-1:xxxxxxxx43:secret:ssn001-xxxxx'

def get_secret():
    try:
        response = client.get_secret_value(
        SecretId=secretid,
        VersionStage='AWSCURRENT',
        )
        return response
    except Exception as e: print(e)

def lambda_handler(event,context):
    try:
        response = create_secret()
        print(response['ARN'])
        response = get_secret()
        print(response['SecretString'])
    except Exception as e: print(e)
```    
