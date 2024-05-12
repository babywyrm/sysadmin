//
// openfire_decrypt
// https://github.com/c0rdis/openfire_decrypt/tree/master
//


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
