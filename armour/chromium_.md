```
#include <tunables/global>

profile podman-container-exec {
    #include <abstractions/base>

    # Define immutable rules for the container filesystem
    deny /** w,
    deny /** wlkix,

    # Define specific rules for the directory containing ChromeDriver and Chrome
    /path/to/chromedriver rix,
    /path/to/chromedriver/* ix,
    /path/to/chromedriver/chromedriver x,
    /path/to/chromedriver/chromedriver/** ix,
    /path/to/chrome rix,
    /path/to/chrome/* ix,
    /path/to/chrome/chrome x,
    /path/to/chrome/chrome/** ix,
}
```
In this profile:

deny /** w denies write access to all files and directories in the container filesystem.

deny /** wlkix denies read, write, lock, create, unlink, link, and execute permissions for all files and directories in the container filesystem.

/path/to/chromedriver and /path/to/chrome are assumed to be the directories containing the ChromeDriver and Chrome binaries, respectively.

/path/to/chromedriver and /path/to/chrome are given read and execute permissions (rix) to access their contents.

/path/to/chromedriver/chromedriver and /path/to/chrome/chrome are given execute permissions (x) to allow execution.

/path/to/chromedriver/* and /path/to/chrome/* are given inherit execute (ix) permissions to allow execution of files within these directories.

/path/to/chromedriver/chromedriver/** and /path/to/chrome/chrome/** are given inherit execute (ix) permissions to allow execution of files within subdirectories.



To apply this AppArmor profile to a Podman container, save it to a file (e.g., podman-container-exec) and then load it using the apparmor_parser command:

```
sudo apparmor_parser -r -W /path/to/podman-container-exec

```
Then, run the Podman container with the --security-opt flag to specify the AppArmor profile:


podman run --security-opt="apparmor=podman-container-exec" your-image



```
#include <tunables/global>

profile chromium_chrome /usr/bin/chromium-browser {
  # Deny access to all directories except for the writable temporary directory
  deny /,
  deny /** rw,
  deny /**/* rw,
  /tmp/ rw,
  /tmp/** rw,
  
  # Allow basic network access
  network,
  
  # Allow access to necessary libraries and resources
  /usr/bin/chromium-browser mr,
  /usr/bin/chromium-browser-* mr,
  /usr/lib/chromium-browser/** mr,
  
  # Allow access to fonts and locales
  /usr/share/fonts/** r,
  /usr/share/locale/** r,
  
  # Allow access to temporary files and directories
  /var/tmp/** rw,
  /var/tmp/**/* rw,
  /tmp/** rw,
  /tmp/**/* rw,
}

```

And...


```

chromium-browser --user-data-dir=/path/to/workdir http://example.com

podman run -v /path/to/host/workdir:/path/to/container/workdir --security-opt="apparmor=chromium_chrome" ...


