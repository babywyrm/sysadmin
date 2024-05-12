
##
#
https://hashcat.net/forum/thread-2399.html
#
https://download.igniterealtime.org/openfire/docs/4.1.0/documentation/javadoc/org/jivesoftware/util/Blowfish.html
#
https://github.com/c0rdis/openfire_decrypt
#
https://github.com/shakaw/openfire-password-decrypt
#
##

Threaded Mode
openfire hash
crackall Offline
Member
***
Posts: 65
Threads: 18
Joined: Jun 2013
#1Rainbow  06-22-2013, 11:55 PM
This hashes from openfire (jabber-server), make by me from admin console

passwd:admin
bfdebe31af3af230f38c6cdc8c436287d5ef3b64ba2f4787

passwd:123456
ee912d51ff70ddd3dbf295d37876f14e7f73ecd0b6dd1076

and also have hashes in two times long, also from openfire

in docs of openfire mention SHA-1 and Blowfish alogitm
which algoritm is use?
neither brute software not recognise this
hashcat can brute this?
which crackware can brute this?
Find
philsmd Offline
I'm phil
******
Posts: 2,267
Threads: 16
Joined: Feb 2013
#206-23-2013, 12:03 AM (This post was last modified: 06-23-2013, 12:50 AM by philsmd.)
I'm no openfire expert. Maybe this is the answer: http://stackoverflow.com/a/1126544
?
This seems to be also interesting: http://svn.igniterealtime.org/svn/repos/...wfish.java
Find
crackall Offline
Member
***
Posts: 65
Threads: 18
Joined: Jun 2013
#306-23-2013, 01:01 AM
in my file openfire.xml not mention any passwordType
Find
philsmd Offline
I'm phil
******
Posts: 2,267
Threads: 16
Joined: Feb 2013
#406-23-2013, 08:06 AM (This post was last modified: 06-23-2013, 01:55 PM by philsmd.)
As said, I am no expert but it seems that there is some standard and you could change it. Anyway what the authentication code does is basically (I quickly looked at the source - you can download it here: http://www.igniterealtime.org/downloads/source.jsp):

Code:
if (encrypted != null) {
...
return AuthFactory.decryptPassword(encrypted);
}

and
Code:
public static String decryptPassword(String encryptedPassword) {
...
Blowfish cipher = getCipher();
...
return cipher.decryptString(encryptedPassword);
}

The Blowfish code is in link above too.
Had a quick look at what OpenFire does and it is basically true what we said, but it does use SHA1 *AND* blowfish, basically.
What one needs to have to decrypt the encrypted password (yes, they are encrypted not hashed, but there is also a SHA1 hash of the passwordKey field involved) is a passwordKey + the encrypted password. The first 8 bytes (16 chars, 8 hex) of the encrypted password is the initialization vector, the blowfish CBC key is stored in the database as "passwordKey" (<- this is SHA1 hashed before used as key to blowfish CBC).

An example (self-generated - you can download OpenFire for free and install it - hope it is fine that I post this encrypted password here for research purpose, otherwise remove it):
Code:

```plain: hashcat
column "encryptedPassword" (ofUser): 08f62fb6091259a2be869ae0ace90f600ec3729a9d5d4683
column "passwordKey" (OFPROPERTY): UaNTQtUV6S7kwm9

Java code (reduced to what we need):
Code:
import javax.crypto.Cipher;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class OpenFireDecryptPass
{
  public static void main(String[] argv) throws Exception
  {
    if (argv.length < 2)
    {
      System.out.println("[-] Please specify the encypted password and the \"passwordKey\"");
      return;
    }
    
    MessageDigest md = MessageDigest.getInstance ("SHA-1");

    byte[] keyParam = md.digest (argv[1].getBytes ("utf8"));
    byte[] ivBytes  = hex2bytes (argv[0].substring (0, 16));
    byte[] encryptedString = hex2bytes (argv[0].substring (16)); // 8 * 2 (since hex)

    IvParameterSpec iv = new IvParameterSpec (ivBytes);
    SecretKeySpec key  = new SecretKeySpec (keyParam, "Blowfish");

    Cipher cipher = Cipher.getInstance ("Blowfish/CBC/PKCS5Padding");
    cipher.init (Cipher.DECRYPT_MODE, key, iv);
    byte[] decrypted = cipher.doFinal (encryptedString);

    String decryptedString = bytes2hex (decrypted);

    System.out.println (new String(decrypted) + " (hex: " + decryptedString + ")");
  }

  public static byte[] hex2bytes(String str)
  {
    if (str == null || str.length() < 2) return null;
    else
    {
      int len = str.length() / 2;
      byte[] buffer = new byte[len];

      for (int i = 0; i < len; i++) buffer[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);

      return buffer;
    }

  }

  public static String bytes2hex(byte[] data)
  {
    if (data == null) return null;
    else
    {
      int len = data.length;

      String str = "";

      for (int i = 0; i < len; i++)
      {
        if ((data[i] & 0xFF) < 16) str = str + "0" + java.lang.Integer.toHexString(data[i] & 0xFF);
        else str = str + java.lang.Integer.toHexString(data[i] & 0xFF);
      }
      return str.toUpperCase();
    }
  }
}
```
How to run:
Code:
javac OpenFireDecryptPass.java; java OpenFireDecryptPass 08f62fb6091259a2be869ae0ace90f600ec3729a9d5d4683 UaNTQtUV6S7kwm9

So basically this is "just" encryption and I think if one gets the encrypted password, one may also have the passwordKey (since it is stored in the same database).
It is also kind of strange why the passwordKey needs to be (stored) in plain and not in SHA-1 directly, maybe this is because this passwordKey is used elsewhere too. I don't know.
