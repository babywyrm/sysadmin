##
#
https://pmd.github.io/pmd/pmd_rules_vf_security.html
#
##


Security
Rules that flag potential security flaws.
VfCsrf ✏️️
Since: PMD 5.6.0

Priority: Medium (3)

Avoid calling VF action upon page load as the action becomes vulnerable to CSRF.

This rule is defined by the following Java class: net.sourceforge.pmd.lang.vf.rule.security.VfCsrfRule

Example(s):

<apex:page controller="AcRestActionsController" action="{!csrfInitMethod}" >
Use this rule by referencing it:

<rule ref="category/vf/security.xml/VfCsrf" />
VfHtmlStyleTagXss ✏️️
Since: PMD 6.31.0

Priority: Medium (3)

Checks for the correct encoding in <style/> tags in Visualforce pages.

The rule is based on Salesforce Security’s recommendation to prevent XSS in Visualforce as mentioned on Secure Coding Cross Site Scripting.

In order to avoid cross site scripting, the relevant encoding must be used in HTML tags. The rule expects URLENCODING or JSINHTMLENCODING for URL-based style values and any kind of encoding (e.g. HTMLENCODING) for non-url style values.

See also VfUnescapeEl to check escaping in other places on Visualforce pages.

This rule is defined by the following Java class: net.sourceforge.pmd.lang.vf.rule.security.VfHtmlStyleTagXssRule

Example(s):

```
<apex:page>
    <style>
        div {
            background: url('{!XSSHere}'); // Potential XSS
        }
        div {
            background: url('{!URLENCODE(XSSHere)}'); // correct encoding
        }
    </style>
</apex:page>
```
Use this rule by referencing it:

<rule ref="category/vf/security.xml/VfHtmlStyleTagXss" />
VfUnescapeEl ✏️️
Since: PMD 5.6.0

Priority: Medium (3)

Avoid unescaped user controlled content in EL as it results in XSS.

This rule is defined by the following Java class: net.sourceforge.pmd.lang.vf.rule.security.VfUnescapeElRule

Example(s):

<apex:outputText value="Potential XSS is {! here }" escape="false" />
Use this rule by referencing it:

<rule ref="category/vf/security.xml/VfUnescapeEl" />
