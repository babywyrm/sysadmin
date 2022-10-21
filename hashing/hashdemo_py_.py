##
##
#
https://github.com/apscandy/database-hash-demo-python
#
##
##


Salt and pepper demo
This is a demo of how salt and pepper work in a theoretical aspect, and is intended for educational purposes. PLEASE DO NOT USE IN PRODUCTION

Why
The question everyone will ask at some point, salt and pepper is indented to address the short comings of storing hashed passwords in a database. What are the aforementioned short comings? Let’s say we are using authentication model without salt or pepper in place and two users have the same passwords, in the event a hacker gets access to the database the hacker can see who has the same password making it more effective for a hacker to crack one hash and get access to anyone with the same password.

Avalanche effect
The avalanche effect is one of the most desirable effects in cryptography. The avalanche effect is simply put; if you change one single bit in the plain text it snowballs and changes the output of the hash entirely. Cool right? that means if I change the "A" in Andrew to "a" I get a different hash. Remember this as the concept will get taken to the extreme with salts.

Salt
The process of salting a password is fairly simple it's just adding a random sequence of bits to the plain text which subsequently triggers the avalanche effect from earlier. One downside is the salt typically gets stored in the database with the hash, so in the event a hacker gets access to the database they will have the salt to attempt a rainbow table attack. The next concept we will cover will help prevent this.


#########################################
#########################################

def salt_generator()->str:
    salt = ''
    for _ in range(0, 64):
        salt += random.choice(string.ascii_letters+string.digits)
    return str(salt)
Here is an example of how you would generate a salt for a user, this one makes a salt string of 64 characters making for a possible 9.6196304190416 x 10^111 combinations.

96 1963041904 1620901435 3125244491 2446413079 5720328478 1904170638 1939592816 6869436184 4273110973 8401260761 8805661696
Pepper
If salt is adding randomness to a password what is pepper then? Pepper is adding a reversible hidden randomness to a password, emphasis on hidden as it's not stored with the salt or on a database, there are 3 types of salt each offering a different level of security with its own trade-offs, if you are wondering what they are is "Shared Secret Pepper", "Unique Pepper Per User" and "Randomly Selected Pepper". For this demo I have selected to use the "Shared Secret Pepper" to keep the concept ease for everyone to understand.

def pepper(password:str)->str:
    password = password[::-1]
    return password
In this example I have a simple little algorithm the just reverses the string I.E. "Hello" gets turned into "elloH" thats it. But this alone will trigger the avalanche effect.

Python code examples
How do we add a password to a database with salt and pepper

@database_creation
def database_add_user_salt_and_pepper(username:str, password:str)->None:
    salt = salt_generator()
    password = pepper(password)
    password = password + salt
    password = hash_password(password)
    with connection_to_database:
        database_cursor.execute(
            'INSERT INTO passwords VALUES (:username, :password, :salt)', 
            {'username': username, 'password': password, "salt": salt})
How do we check if a password equals the stored hash?.

def salt_hash_check(password:str, database_hash:str, database_salt:str)->bool:
    password = pepper(password)
    password = hash_password(password + database_salt)
    if password == database_hash:
        return True
    else:
        return False
