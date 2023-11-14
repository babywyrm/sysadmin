
##
#
https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual#scripted-install
#
##



 2006  ln -s dotnet /usr/bin/dotnet
 2011  vi shell.csproj
 2016  vi shell.cs
 2017  cp shell.cs reverse.cs
 2018  cp shell.csproj reverse.csproj
 2022  dotnet new console
 2025  ./dotnet new console
 2029  mkdir reverse
 2030  cp reverse* reverse
 2037  cd ..
 2041  vi .dotnet.csproj
 2043  cd reverse
 2045  dotnet
 2049  cp reverse.csproj reverse.csproj.save
 2050  ../dotnet new console
 2051  ../dotnet new console --force
 2054  cat reverse.cs
 2056  cat reverse.csproj
 2060  cp reverse.cs Program.cs
 2063  vi Program.cs
 2066  dotnet build
 2072  vi reverse.csproj
 2076  rm Program.cs
 2077  ../dotnet build
 2080  cd bin
 2082  cd Debug
 2085  cd net45
 2087  ls -la
 2088  ls
 2089  base64 rev.exe -w0
 2090  cat reverse.exe | base64 -w0


##
##

Install .NET on Linux by using an install script or by extracting binaries

    Article
    08/17/2023

In this article

    .NET releases
    Dependencies
    Scripted install
    Manual install

This article demonstrates how to install the .NET SDK or the .NET Runtime on Linux by using the install script or by extracting the binaries. For a list of distributions that support the built-in package manager, see Install .NET on Linux.

Install the SDK (which includes the runtime) if you want to develop .NET apps. Or, if you only need to run apps, install the Runtime. If you're installing the Runtime, we suggest you install the ASP.NET Core Runtime as it includes both .NET and ASP.NET Core runtimes.

Use the dotnet --list-sdks and dotnet --list-runtimes commands to see which versions are installed. For more information, see How to check that .NET is already installed.
.NET releases

There are two types of supported releases, Long Term Support (LTS) releases or Standard Term Support (STS). The quality of all releases is the same. The only difference is the length of support. LTS releases get free support and patches for 3 years. STS releases get free support and patches for 18 months. For more information, see .NET Support Policy.

The following table lists the support status of each version of .NET (and .NET Core):
✔️ Supported 	❌ Unsupported
7 (STS) 	5
6 (LTS) 	3.1
	3.0
	2.2
	2.1
	2.0
	1.1
	1.0
Dependencies

It's possible that when you install .NET, specific dependencies may not be installed, such as when manually installing. The following list details Linux distributions that are supported by Microsoft and have dependencies you may need to install. Check the distribution page for more information:

    Alpine
    Debian
    CentOS
    Fedora
    RHEL and CentOS Stream
    SLES
    Ubuntu

For generic information about the dependencies, see Self-contained Linux apps.
RPM dependencies

If your distribution wasn't previously listed, and is RPM-based, you may need the following dependencies:

    krb5-libs
    libicu
    openssl-libs

If the target runtime environment's OpenSSL version is 1.1 or newer, install compat-openssl10.
DEB dependencies

If your distribution wasn't previously listed, and is debian-based, you may need the following dependencies:

    libc6
    libgcc1
    libgssapi-krb5-2
    libicu67
    libssl1.1
    libstdc++6
    zlib1g

Common dependencies

If the .NET app uses the System.Drawing.Common assembly, libgdiplus will also need to be installed. Because System.Drawing.Common is no longer supported on Linux, this only works on .NET 6 and requires setting the System.Drawing.EnableUnixSupport runtime configuration switch.

You can usually install a recent version of libgdiplus by adding the Mono repository to your system.
Scripted install

The dotnet-install scripts are used for automation and non-admin installs of the SDK and Runtime. You can download the script from https://dot.net/v1/dotnet-install.sh. When .NET is installed in this way, you must install the dependencies required by your Linux distribution. Use the links in the Install .NET on Linux article for your specific Linux distribution.

Important

Bash is required to run the script.

You can download the script with wget:
Bash

wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh

Before running this script, make sure you grant permission for this script to run as an executable:
Bash

chmod +x ./dotnet-install.sh

The script defaults to installing the latest long term support (LTS) SDK version, which is .NET 6. To install the latest release, which may not be an (LTS) version, use the --version latest parameter.
Bash

./dotnet-install.sh --version latest

To install .NET Runtime instead of the SDK, use the --runtime parameter.
Bash

./dotnet-install.sh --version latest --runtime aspnetcore

You can install a specific major version with the --channel parameter to indicate the specific version. The following command installs .NET 7.0 SDK.
Bash

./dotnet-install.sh --channel 7.0

For more information, see dotnet-install scripts reference.

To enable .NET on the command line, see Set environment variables system-wide.
Manual install

As an alternative to the package managers, you can download and manually install the SDK and runtime. Manual installation is commonly used as part of continuous integration testing or on an unsupported Linux distribution. For a developer or user, it's better to use a package manager.

Download a binary release for either the SDK or the runtime from one of the following sites. The .NET SDK includes the corresponding runtime:

    ✔️ .NET 7 downloads
    ✔️ .NET 6 downloads
    All .NET Core downloads

Extract the downloaded file and use the export command to set DOTNET_ROOT to the extracted folder's location and then ensure .NET is in PATH. Exporting DOTNET_ROOT makes the .NET CLI commands available in the terminal. For more information about .NET environment variables, see .NET SDK and CLI environment variables.

Different versions of .NET can be extracted to the same folder, which coexist side-by-side.
Example

The following commands set the environment variable DOTNET_ROOT to the current working directory followed by .dotnet. They then create the directory if it doesn't exist and extract the contents of the file specified by the DOTNET_FILE environment variable to the .dotnet directory. Both the .dotnet directory and its tools subdirectory are added to the PATH environment variable.

Important

If you run these commands, remember to change the DOTNET_FILE value to the name of the .NET binary you downloaded.
Bash

DOTNET_FILE=dotnet-sdk-7.0.100-linux-x64.tar.gz
export DOTNET_ROOT=$(pwd)/.dotnet

mkdir -p "$DOTNET_ROOT" && tar zxf "$DOTNET_FILE" -C "$DOTNET_ROOT"

export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools

The preceding install script approach allows installing different versions into separate locations so you can choose explicitly which one to use by which app. However, you can still install multiple versions of .NET to the same folder.
Verify downloaded binaries

After downloading an installer, verify it to make sure that the file hasn't been changed or corrupted. You can verify the checksum on your computer and then compare it to what was reported on the download website.

When you download an installer or binary from an official download page, the checksum for the file is displayed. Select the Copy button to copy the checksum value to your clipboard.

The .NET download page with checksum

Use the sha512sum command to print the checksum of the file you've downloaded. For example, the following command reports the checksum of the dotnet-sdk-7.0.304-linux-x64.tar.gz file:
Bash

$ sha512sum dotnet-sdk-7.0.304-linux-x64.tar.gz
f4b7d0cde432bd37f445363b3937ad483e5006794886941e43124de051475925b3cd11313b73d2cae481ee9b8f131394df0873451f6088ffdbe73f150b1ed727  dotnet-sdk-7.0.304-linux-x64.tar.gz

Compare the checksum with the value provided by the download site.

Important

Even though a Linux file is shown in these examples, this information equally applies to macOS.
Use a checksum file to validate

The .NET release notes contain a link to a checksum file you can use to validate your downloaded file. The following steps describe how to download the checksum file and validate a .NET install binary:

    The release notes page for .NET 7 on GitHub at https://github.com/dotnet/core/tree/main/release-notes/7.0 contains a section named Releases. The table in that section links to the downloads and checksum files for each .NET 7 release:

    The github release notes version table for .NET

    Select the link for the version of .NET that you downloaded. The previous section used .NET SDK 7.0.304, which is in the .NET 7.0.7 release.

    In the release page, you can see the .NET Runtime and .NET SDK version, and a link to the checksum file:

    The download table with checksums for .NET

    Copy the link to the checksum file.

    Use the following script, but replace the link to download the appropriate checksum file:
    Bash 

curl -O https://dotnetcli.blob.core.windows.net/dotnet/checksums/7.0.7-sha.txt

With both the checksum file and the .NET release file downloaded to the same directory, use the sha512sum -c {file} --ignore-missing command to validate the downloaded file.

When validation passes, you see the file printed with the OK status:
Bash

$ sha512sum -c 7.0.7-sha.txt --ignore-missing
dotnet-sdk-7.0.304-linux-x64.tar.gz: OK

If you see the file marked as FAILED, the file you downloaded isn't valid and shouldn't be used.
Bash

    $ sha512sum -c 7.0.7-sha.txt --ignore-missing
    dotnet-sdk-7.0.304-linux-x64.tar.gz: FAILED
    sha512sum: WARNING: 1 computed checksum did NOT match
    sha512sum: 7.0.7-sha.txt: no file was verified

Set environment variables system-wide

If you used the previous install script, the variables set only apply to your current terminal session. Add them to your shell profile. There are many different shells available for Linux and each has a different profile. For example:

    Bash Shell: ~/.bash_profile, ~/.bashrc
    Korn Shell: ~/.kshrc or .profile
    Z Shell: ~/.zshrc or .zprofile

Set the following two environment variables in your shell profile:

    DOTNET_ROOT

    This variable is set to the folder .NET was installed to, such as $HOME/.dotnet:
    Bash 

export DOTNET_ROOT=$HOME/.dotnet

PATH

This variable should include both the DOTNET_ROOT folder and the user's .dotnet/tools folder:
Bash

    export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools

Next steps
