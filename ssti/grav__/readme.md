     
##
#
https://github.com/advisories/GHSA-whr7-m3f8-mpm8
#
##

Grav Server-side Template Injection (SSTI) via Twig Default Filters
High severity GitHub Reviewed Published Jun 14, 2023 in getgrav/grav • Updated Nov 5, 2023
Vulnerability details
Dependabot alerts 0
Package
getgrav/grav (
Composer
)
Affected versions
< 1.7.42
Patched versions
1.7.42
Description

Hi,

actually we have sent the bug report to security@getgrav.org on 27th March 2023 and on 10th April 2023.
Grav Server-side Template Injection (SSTI) via Twig Default Filters
Summary:
Product 	Grav CMS
Vendor 	Grav
Severity 	High - Users with login access to Grav Admin panel and page creation/update permissions are able to obtain remote code/command execution
Affected Versions 	<= v1.7.40 (Commit 685d762) (Latest version as of writing)
Tested Versions 	v1.7.40
Internal Identifier 	STAR-2023-0008
CVE Identifier 	TBD
CWE(s) 	CWE-184: Incomplete List of Disallowed Inputs, CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine
CVSS3.1 Scoring System:

Base Score: 7.2 (High)
Vector String: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
Metric 	Value
Attack Vector (AV) 	Network
Attack Complexity (AC) 	Low
Privileges Required (PR) 	High
User Interaction (UI) 	None
Scope (S) 	Unchanged
Confidentiality (C) 	High
Integrity (I) 	High
Availability (A) 	High
Product Overview:

Grav is a PHP-based flat-file content management system (CMS) designed to provide a fast and simple way to build websites. It supports rendering of web pages written in Markdown and Twig expressions, and provides an administration panel to manage the entire website via an optional Admin plugin.
Vulnerability Summary:

The patch for CVE-2022-2073, a server-side template injection vulnerability in Grav leveraging the default filter() function, did not block other built-in functions exposed by Twig's Core Extension that could be used to invoke arbitrary unsafe functions, thereby allowing for remote code execution.
Vulnerability Details:

Twig comes with an extension known as the Core Extension that is enabled by default when initialising a new Twig environment. Twig's Core Extension provides multiple built-in filters, such as the filter() function, which can be used in Twig templates.

CVE-2022-2073 leverages the default filter() filter function in Twig to invoke arbitrary unsafe functions. This was patched by overriding the default filter() filter function in commit 9d6a2d of Grav v1.7.34 to perform validation checks on the arguments passed to filter():

...
```
class GravExtension extends AbstractExtension implements GlobalsInterface
{
    ...
    public function getFilters(): array
    {
        return [
            ...
            // Security fix
+           new TwigFilter('filter', [$this, 'filterFilter'], ['needs_environment' => true]),
        ];
    }
    
    ...

+   /**
+    * @param Environment $env
+    * @param array $array
+    * @param callable|string $arrow
+    * @return array|CallbackFilterIterator
+    * @throws RuntimeError
+    */
+   function filterFilter(Environment $env, $array, $arrow)
+   {
+       if (is_string($arrow) && Utils::isDangerousFunction($arrow)) {
+           throw new RuntimeError('Twig |filter("' . $arrow . '") is not allowed.');
+       }
+
+       return \twig_array_filter($env, $array, $arrow);
+   }
}
```
However, looking at the source code of /src/Extension/CoreExtension.php of Twig, alternative default Twig filters could also be used invoke arbitrary functions:

...
```
class CoreExtension extends AbstractExtension
{
    ...
    public function getFilters(): array
    {
        return [
            ...
            // array helpers
            ...
            new TwigFilter('filter', 'twig_array_filter', ['needs_environment' => true]), // unsafe
            new TwigFilter('map', 'twig_array_map', ['needs_environment' => true]), // unsafe
            new TwigFilter('reduce', 'twig_array_reduce', ['needs_environment' => true]), // unsafe
        ];
    }
```
The three filter functions above respectively call array_filter(), array_map() and array_reduce(). Since only filter() is being overriden by Grav to ensure that the callable passed to filter() does not result in the invocation of an unsafe function, the other two functions (i.e. map() and reduce()) could be used by an authenticated attacker that is able to inject and render malicious templates to gain remote code execution.
Exploit Conditions:

This vulnerability can be exploited if the attacker has access to:

    an administrator account, or
    a non-administrator, user account that are granted the following permissions:
        login access to Grav admin panel, and
        page creation or update rights

Reproduction Steps:

    Log in to Grav Admin using an administrator account.
    Navigate to Accounts > Add, and ensure that the following permissions are assigned when creating a new low-privileged user:
        Login to Admin - Allowed
        Page Update - Allowed
    Log out of Grav Admin, and log back in using the account created in step 2.
    Navigate to http://<grav_installation>/admin/pages/home.
    Click the Advanced tab and select the checkbox beside Twig to ensure that Twig processing is enabled for the modified webpage.
    Under the Content tab, insert the following payload within the editor:

    {{ ['id'] | map('system') }}
    {{ ['id'] | reduce('system') }}

    Click the Preview button. Observe that the output of the id shell command is returned in the preview.

Suggested Mitigations:

Override the built-in Twig map() and reduce() filter functions in system/src/Grav/Common/Twig/Extension/GravExtension.php to validate the argument passed to the filter in $arrow.

For example:

...
class GravExtension extends AbstractExtension implements GlobalsInterface
{
    ...
    public function getFilters(): array
    {
        return [
            ...
            // Security fix
            new TwigFilter('filter', [$this, 'filterFilter'], ['needs_environment' => true]),
+           new TwigFilter('map', [$this, 'mapFilter'], ['needs_environment' => true]),
+           new TwigFilter('reduce', [$this, 'reduceFilter'], ['needs_environment' => true]),
        ];
    }

    ...
+   /**
+    * @param Environment $env
+    * @param array $array
+    * @param callable|string $arrow
+    * @return array|CallbackFilterIterator
+    * @throws RuntimeError
+    */
+   function mapFilter(Environment $env, $array, $arrow)
+   {
+       if (!$arrow instanceof Closure && !is_string($arrow) || Utils::isDangerousFunction($arrow)) {
+           throw new RuntimeError('Twig |map("' . $arrow . '") is not allowed.');
+       }
+
+       return \twig_array_map($env, $array, $arrow);
+   }
+ 
+   /**
+    * @param Environment $env
+    * @param array $array
+    * @param callable|string $arrow
+    * @return array|CallbackFilterIterator
+    * @throws RuntimeError
+    */
+   function reduceFilter(Environment $env, $array, $arrow)
+   {
+       if (!$arrow instanceof Closure && !is_string($arrow) || Utils::isDangerousFunction($arrow)) {
+           throw new RuntimeError('Twig |reduce("' . $arrow . '") is not allowed.');
+       }
+
+       return \twig_array_reduce($env, $array, $arrow);
+   }
}

Detection Guidance:

The following strategies may be used to detect potential exploitation attempts.

    Searching within Markdown pages using the following shell command:
    grep -Priz -e '\|\s*(map|reduce)\s*\(' /path/to/webroot/user/pages/
    Searching within Doctrine cache data using the following shell command:
    grep -Priz -e '\|\s*(map|reduce)\s*\('  --include '*.doctrinecache.data' /path/to/webroot/cache/
    Searching within Twig cache using the following shell command:
    grep -Priz -e 'twig_array_(map|reduce)' /path/to/webroot/cache/twig/
    Searching within compiled Twig template files using the following shell command:
    grep -Priz -e '\|\s*(map|reduce)\s*\(' /path/to/webroot/cache/compiled/files/

Note that it is not possible to detect indicators of compromise reliably using the Grav log file (located at /path/to/webroot/logs/grav.log by default), as successful exploitation attempts do not generate any additional logs. However, it is worthwhile to examine any PHP errors or warnings logged to determine the existence of any failed exploitation attempts.
Credits:

Ngo Wei Lin (@Creastery) & Wang Hengyue (@w_hy_04) of STAR Labs SG Pte. Ltd. (@starlabs_sg)
Vulnerability Disclosure:

This vulnerability report is subject to a 120 day disclosure deadline as per STAR Labs SG Pte. Ltd.'s Vulnerability Disclosure Policy. After 120 days have elapsed, the vulnerability report will be published to the public by STAR Labs SG Pte. Ltd. (STAR Labs).

The scheduled disclosure date is 25th July, 2023. Disclosure at an earlier date is also possible if agreed upon by all parties.

Kindly note that STAR Labs reserved and assigned the following CVE identifiers to the respective vulnerabilities presented in this report:

    CVE-2023-30596
    Server-side Template Injection (SSTI) in getgrav/grav <= v1.7.40 allows Grav Admin users with page creation or update rights to bypass the dangerous functions denylist check in GravExtension.filterFilter() and to achieve remote code execution via Twig's default filters map() and reduce(). This is a bypass of CVE-2022-2073.

References

    GHSA-whr7-m3f8-mpm8
    https://nvd.nist.gov/vuln/detail/CVE-2023-34448
    getgrav/grav@244758d
    getgrav/grav@71bbed1
    getgrav/grav@8c2c1cb
    getgrav/grav@9d01140
    https://github.com/twigphp/Twig/blob/v1.44.7/src/Environment.php#L148
    https://huntr.dev/bounties/3ef640e6-9e25-4ecb-8ec1-64311d63fe66/
    https://www.github.com/getgrav/grav/commit/9d6a2dba09fd4e56f5cdfb9a399caea355bfeb83

