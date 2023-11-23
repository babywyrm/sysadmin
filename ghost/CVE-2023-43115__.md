# ghostscript-CVE-2023-43115
A small write-up with examples to help understand CVE-2023-43115.

> [!WARNING] 
> I wrote this mainly for myself to understand the problem and to learn about cybersecurity. So there may be errors.

## The Problem
To use the IJS device (improved inkjet printing), ghostscript needs to start an IJS server. In order to do this, it reads a path from the IjsServer parameter, which can be set to point to any arbitrary file on the file system and then executes that file. Here it is easy to see how this could potentially be misused, e.g. you could run the following ghostscript command to print hello world.

```console
❯ gs -sDEVICE=ijs -sIjsServer="bash -c 'echo Hello World>&2'"
GPL Ghostscript 9.55.0 (2021-09-27)
Copyright (C) 2021 Artifex Software, Inc.  All rights reserved.
This software is supplied under the GNU AGPLv3 and comes with NO WARRANTY:
see the file COPYING for details.
Hello World
```
In it self this isen´t that problematic since this parameter has to be supplied by the user. However it is also possible to set this device and the IJsServer parameter inside a postscript script.
See for example `attack_example_*.ps` (execute with `gs FILENAME`). This in turn could allow an attack to execute code on the machine running this script. But, this problem is known and officially [documented](https://ghostscript.com/docs/9.56.1/Devices.htm#IJS) and could be **prevented by setting LockSafetyParams** to true.

To leverage this CVE while LockSafetyParams is enabled, an attacker would need a working exploit to change LockSafetyParams. However, if such an exploit is available, there could be a number of other possible attack vectors depending on the version used.

The author of the fix Ken Sharp called the mentioned LockSafetyParams security solution a hacky because it is implemented in Postscript and is thus vulnerable to Postscript programs. This led to several security issues where it was possible to overwrite this value (for an example see [CVE-2018-19475 writeup](https://securitylab.github.com/research/ghostscript-CVE-2018-19475/)
). The fix **changes the protection mechanism** that prevents setting the IjsServer path from LockSaftyParams **to** the new **-dSAFER** parameter, which cannot be affected by postscript code.

> [!NOTE] 
> The [Documentation](https://ghostscript.com/docs/9.55.0/Devices.htm#IJS) of version 9.55.0 allready states to use the -dSAFER parameter which seems to be a documentation error.

## Sources and further reading
- [CVE-2023-43115](https://nvd.nist.gov/vuln/detail/CVE-2023-43115)
- [Fix commit](https://git.ghostscript.com/?p=ghostpdl.git;a=commit;h=e59216049cac290fb437a04c4f41ea46826cfba5)
- [CVE-2018-19475 writeup](https://securitylab.github.com/research/ghostscript-CVE-2018-19475/)
- [IJS DOC](https://ghostscript.com/docs/9.56.1/Devices.htm#IJS)
- [LockSaftyParams DOC](https://ghostscript.com/docs/9.55.0/Language.htm#LockSafetyParams)

