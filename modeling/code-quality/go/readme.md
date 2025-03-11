
##
#
https://github.com/securego/gosec
#
##

```
Semgrep:
A powerful multi-language static analysis tool that supports Go, JavaScript, Python, Java, and more. It lets you write custom rules in a human-readable syntax and is great for detecting security vulnerabilities and code smells across various languages.

CodeQL:
Developed by GitHub, CodeQL allows you to query your code as data. It supports multiple languages (including Go, JavaScript, Python, and Java) and can help uncover complex vulnerabilities by running sophisticated queries over your codebase.

Staticcheck:
While primarily focused on code quality, Staticcheck (by Dominikh) also flags potential issues that might lead to vulnerabilities. It's a valuable tool for ensuring your Go code adheres to best practices.

Go Vet:
Included with Go, go vet examines your code and reports suspicious constructs. It’s not as comprehensive as specialized security scanners, but it can catch many common mistakes early.

SonarQube / SonarCloud:
These platforms offer continuous code quality and security analysis across many languages. They integrate well into CI/CD pipelines and can provide detailed dashboards and reports on vulnerabilities and code smells.

Snyk:
Although often used for dependency vulnerability scanning, Snyk also offers static analysis capabilities for code. It supports several languages and integrates well with development workflows to catch issues early.

gosec - Go Security Checker
Inspects source code for security problems by scanning the Go AST and SSA code representation.
```


License
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. You may obtain a copy of the License here.

Project status
CII Best Practices Build Status Coverage Status GoReport GoDoc Docs Downloads Docker Pulls Slack go-recipes

Install
CI Installation
# binary will be $(go env GOPATH)/bin/gosec
curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b $(go env GOPATH)/bin vX.Y.Z

# or install it into ./bin/
curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s vX.Y.Z

# In alpine linux (as it does not come with curl by default)
wget -O - -q https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s vX.Y.Z

# If you want to use the checksums provided on the "Releases" page
# then you will have to download a tar.gz file for your operating system instead of a binary file
wget https://github.com/securego/gosec/releases/download/vX.Y.Z/gosec_vX.Y.Z_OS.tar.gz

# The file will be in the current folder where you run the command
# and you can check the checksum like this
echo "<check sum from the check sum file>  gosec_vX.Y.Z_OS.tar.gz" | sha256sum -c -

gosec --help
GitHub Action
You can run gosec as a GitHub action as follows:
```
name: Run Gosec
on:
  push:
    branches:
      - master
  pull_request:
    branches:
      - master
jobs:
  tests:
    runs-on: ubuntu-latest
    env:
      GO111MODULE: on
    steps:
      - name: Checkout Source
        uses: actions/checkout@v3
      - name: Run Gosec Security Scanner
        uses: securego/gosec@master
        with:
          args: ./...
```
Integrating with code scanning
You can integrate third-party code analysis tools with GitHub code scanning by uploading data as SARIF files.

The workflow shows an example of running the gosec as a step in a GitHub action workflow which outputs the results.sarif file. The workflow then uploads the results.sarif file to GitHub using the upload-sarif action.

name: "Security Scan"
```
# Run workflow each time code is pushed to your repository and on a schedule.
# The scheduled workflow runs every at 00:00 on Sunday UTC time.
on:
  push:
  schedule:
  - cron: '0 0 * * 0'

jobs:
  tests:
    runs-on: ubuntu-latest
    env:
      GO111MODULE: on
    steps:
      - name: Checkout Source
        uses: actions/checkout@v3
      - name: Run Gosec Security Scanner
        uses: securego/gosec@master
        with:
          # we let the report trigger content trigger a failure using the GitHub Security features.
          args: '-no-fail -fmt sarif -out results.sarif ./...'
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          # Path to SARIF file relative to the root of the repository
          sarif_file: results.sarif
```


Local Installation
go install github.com/securego/gosec/v2/cmd/gosec@latest
Usage
Gosec can be configured to only run a subset of rules, to exclude certain file paths, and produce reports in different formats. By default all rules will be run against the supplied input files. To recursively scan from the current directory you can supply ./... as the input argument.

Available rules
G101: Look for hard coded credentials
G102: Bind to all interfaces
G103: Audit the use of unsafe block
G104: Audit errors not checked
G106: Audit the use of ssh.InsecureIgnoreHostKey
G107: Url provided to HTTP request as taint input
G108: Profiling endpoint automatically exposed on /debug/pprof
G109: Potential Integer overflow made by strconv.Atoi result conversion to int16/32
G110: Potential DoS vulnerability via decompression bomb
G111: Potential directory traversal
G112: Potential slowloris attack
G113: Usage of Rat.SetString in math/big with an overflow (CVE-2022-23772)
G114: Use of net/http serve function that has no support for setting timeouts
G115: Potential integer overflow when converting between integer types
G201: SQL query construction using format string
G202: SQL query construction using string concatenation
G203: Use of unescaped data in HTML templates
G204: Audit use of command execution
G301: Poor file permissions used when creating a directory
G302: Poor file permissions used with chmod
G303: Creating tempfile using a predictable path
G304: File path provided as taint input
G305: File traversal when extracting zip/tar archive
G306: Poor file permissions used when writing to a new file
G307: Poor file permissions used when creating a file with os.Create
G401: Detect the usage of MD5 or SHA1
G402: Look for bad TLS connection settings
G403: Ensure minimum RSA key length of 2048 bits
G404: Insecure random number source (rand)
G405: Detect the usage of DES or RC4
G406: Detect the usage of MD4 or RIPEMD160
G407: Detect the usage of hardcoded Initialization Vector(IV)/Nonce
G501: Import blocklist: crypto/md5
G502: Import blocklist: crypto/des
G503: Import blocklist: crypto/rc4
G504: Import blocklist: net/http/cgi
G505: Import blocklist: crypto/sha1
G506: Import blocklist: golang.org/x/crypto/md4
G507: Import blocklist: golang.org/x/crypto/ripemd160
G601: Implicit memory aliasing of items from a range statement (only for Go 1.21 or lower)
G602: Slice access out of bounds
Retired rules
G105: Audit the use of math/big.Int.Exp - CVE is fixed
G307: Deferring a method which returns an error - causing more inconvenience than fixing a security issue, despite the details from this blog post
Selecting rules
By default, gosec will run all rules against the supplied file paths. It is however possible to select a subset of rules to run via the -include= flag, or to specify a set of rules to explicitly exclude using the -exclude= flag.

# Run a specific set of rules
$ gosec -include=G101,G203,G401 ./...

# Run everything except for rule G303
$ gosec -exclude=G303 ./...
CWE Mapping
Every issue detected by gosec is mapped to a CWE (Common Weakness Enumeration) which describes in more generic terms the vulnerability. The exact mapping can be found here.

Configuration
A number of global settings can be provided in a configuration file as follows:

{
    "global": {
        "nosec": "enabled",
        "audit": "enabled"
    }
}
nosec: this setting will overwrite all #nosec directives defined throughout the code base
audit: runs in audit mode which enables addition checks that for normal code analysis might be too nosy
# Run with a global configuration file
$ gosec -conf config.json .
Rule Configuration
Some rules accept configuration flags as well; these flags are documented in RULES.md.

Go version
Some rules require a specific Go version which is retrieved from the Go module file present in the project. If this version cannot be found, it will fallback to Go runtime version.

The Go module version is parsed using the go list command which in some cases might lead to performance degradation. In this situation, the go module version can be easily provided by setting the environment variable GOSECGOVERSION=go1.21.1.

Dependencies
gosec will fetch automatically the dependencies of the code which is being analyzed when go module is turned on (e.g.GO111MODULE=on). If this is not the case, the dependencies need to be explicitly downloaded by running the go get -d command before the scan.

Excluding test files and folders
gosec will ignore test files across all packages and any dependencies in your vendor directory.

The scanning of test files can be enabled with the following flag:

gosec -tests ./...
Also additional folders can be excluded as follows:

 gosec -exclude-dir=rules -exclude-dir=cmd ./...
Excluding generated files
gosec can ignore generated go files with default generated code comment.

// Code generated by some generator DO NOT EDIT.
gosec -exclude-generated ./...
Auto fixing vulnerabilities
gosec can suggest fixes based on AI recommendation. It will call an AI API to receive a suggestion for a security finding.

You can enable this feature by providing the following command line arguments:

ai-api-provider: the name of the AI API provider, currently only geminiis supported.
ai-api-key or set the environment variable GOSEC_AI_API_KEY: the key to access the AI API, For gemini, you can create an API key following these instructions.
ai-endpoint: the endpoint of the AI provider, this is optional argument.
gosec -ai-api-provider="gemini" -ai-api-key="your_key" ./...
Annotating code
As with all automated detection tools, there will be cases of false positives. In cases where gosec reports a failure that has been manually verified as being safe, it is possible to annotate the code with a comment that starts with #nosec.

The #nosec comment should have the format #nosec [RuleList] [-- Justification].

The #nosec comment needs to be placed on the line where the warning is reported.

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402
		},
	}

	client := &http.Client{Transport: tr}
	_, err := client.Get("https://go.dev/")
	if err != nil {
		fmt.Println(err)
	}
}
When a specific false positive has been identified and verified as safe, you may wish to suppress only that single rule (or a specific set of rules) within a section of code, while continuing to scan for other problems. To do this, you can list the rule(s) to be suppressed within the #nosec annotation, e.g: /* #nosec G401 */ or //#nosec G201 G202 G203

You could put the description or justification text for the annotation. The justification should be after the rule(s) to suppress and start with two or more dashes, e.g: //#nosec G101 G102 -- This is a false positive

Alternatively, gosec also supports the //gosec:disable directive, which functions similar to #nosec:

//gosec:disable G101 -- This is a false positive
In some cases you may also want to revisit places where #nosec or //gosec:disable annotations have been used. To run the scanner and ignore any #nosec annotations you can do the following:

gosec -nosec=true ./...
Tracking suppressions
As described above, we could suppress violations externally (using -include/ -exclude) or inline (using #nosec annotations) in gosec. This suppression inflammation can be used to generate corresponding signals for auditing purposes.

We could track suppressions by the -track-suppressions flag as follows:

gosec -track-suppressions -exclude=G101 -fmt=sarif -out=results.sarif ./...
For external suppressions, gosec records suppression info where kind is external and justification is a certain sentence "Globally suppressed".
For inline suppressions, gosec records suppression info where kind is inSource and justification is the text after two or more dashes in the comment.
Note: Only SARIF and JSON formats support tracking suppressions.

Build tags
gosec is able to pass your Go build tags to the analyzer. They can be provided as a comma separated list as follows:

gosec -tags debug,ignore ./...
Output formats
gosec currently supports text, json, yaml, csv, sonarqube, JUnit XML, html and golint output formats. By default results will be reported to stdout, but can also be written to an output file. The output format is controlled by the -fmt flag, and the output file is controlled by the -out flag as follows:

# Write output in json format to results.json
$ gosec -fmt=json -out=results.json *.go
Results will be reported to stdout as well as to the provided output file by -stdout flag. The -verbose flag overrides the output format when stdout the results while saving them in the output file

# Write output in json format to results.json as well as stdout
$ gosec -fmt=json -out=results.json -stdout *.go

# Overrides the output format to 'text' when stdout the results, while writing it to results.json
$ gosec -fmt=json -out=results.json -stdout -verbose=text *.go
Note: gosec generates the generic issue import format for SonarQube, and a report has to be imported into SonarQube using sonar.externalIssuesReportPaths=path/to/gosec-report.json.

Development
CONTRIBUTING.md contains detailed information about adding new rules to gosec.

Build
You can build the binary with:

make
Note on Sarif Types Generation
Install the tool with :

go get -u github.com/a-h/generate/cmd/schema-generate
Then generate the types with :

schema-generate -i sarif-schema-2.1.0.json -o mypath/types.go
Most of the MarshallJSON/UnmarshalJSON are removed except the one for PropertyBag which is handy to inline the additional properties. The rest can be removed. The URI,ID, UUID, GUID were renamed so it fits the Go convention defined here

Tests
You can run all unit tests using:

make test
Release
You can create a release by tagging the version as follows:

git tag v1.0.0 -m "Release version v1.0.0"
git push origin v1.0.0
The GitHub release workflow triggers immediately after the tag is pushed upstream. This flow will release the binaries using the goreleaser action and then it will build and publish the docker image into Docker Hub.

The released artifacts are signed using cosign. You can use the public key from cosign.pub file to verify the signature of docker image and binaries files.

The docker image signature can be verified with the following command:

cosign verify --key cosign.pub securego/gosec:<TAG>
The binary files signature can be verified with the following command:

cosign verify-blob --key cosign.pub --signature gosec_<VERSION>_darwin_amd64.tar.gz.sig  gosec_<VERSION>_darwin_amd64.tar.gz
Docker image
You can also build locally the docker image by using the command:

make image
You can run the gosec tool in a container against your local Go project. You only have to mount the project into a volume as follows:

docker run --rm -it -w /<PROJECT>/ -v <YOUR PROJECT PATH>/<PROJECT>:/<PROJECT> securego/gosec /<PROJECT>/...
Note: the current working directory needs to be set with -w option in order to get successfully resolved the dependencies from go module file

Generate TLS rule
The configuration of TLS rule can be generated from Mozilla's TLS ciphers recommendation.

First you need to install the generator tool:

go get github.com/securego/gosec/v2/cmd/tlsconfig/...
You can invoke now the go generate in the root of the project:

go generate ./...
This will generate the rules/tls_config.go file which will contain the current ciphers recommendation from Mozilla.

Who is using gosec?
This is a list with some of the gosec's users.
