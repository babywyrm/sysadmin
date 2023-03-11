
##
#
https://www.kb.cert.org/vuls/id/475445
#
##


HomeNotesCurrent:VU#475445
Multiple SAML libraries may allow authentication bypass via incorrect XML canonicalization and DOM traversal
Vulnerability Note VU#475445
Original Release Date: 2018-02-27 | Last Revised: 2018-06-05
   
Overview
Multiple SAML libraries may incorrectly utilize the results of XML DOM traversal and canonicalization APIs in such a way that an attacker may be able to manipulate the SAML data without invalidating the cryptographic signature, allowing the attack to potentially bypass authentication to SAML service providers.

Description
CWE-287: Improper Authentication

Security Assertion Markup Language (SAML) is an XML-based markup language for security assertions regarding authentication and permissions, most commonly used for single sign-on (SSO) services.

Some XML DOM traversal and canonicalization APIs may be inconsistent in handling of comments within XML nodes. Incorrect use of these APIs by some SAML libraries results in incorrect parsing of the inner text of XML nodes such that any inner text after the comment is lost prior to cryptographically signing the SAML message. Text after the comment therefore has no impact on the signature on the SAML message.

A remote attacker can modify SAML content for a SAML service provider without invalidating the cryptographic signature, which may allow attackers to bypass primary authentication for the affected SAML service provider

The following CVEs are assigned:

CVE-2017-11427 - OneLogin’s "python-saml"
CVE-2017-11428 - OneLogin’s "ruby-saml"
CVE-2017-11429 - Clever’s "saml2-js"
CVE-2017-11430 - "OmniAuth-SAML"
CVE-2018-0489 - Shibboleth openSAML C++
CVE-2018-5387 - Wizkunde SAMLBase

More information is available in the researcher's blog post.

Impact
By modifying SAML content without invalidating the cryptographic signature, a remote, unauthenticated attacker may be able to bypass primary authentication for an affected SAML service provider.

Solution
Apply updates

Affected SAML service providers should update software to utilize the latest releases of affected SAML libraries. Please see the vendor list below for more information.


##
##

SAML vulnerability abuses SSO to impersonate other users
Jessica Haworth 01 March 2018 at 14:15 UTC
Updated: 09 October 2019 at 10:23 UTC
Secure Development Vulnerabilities
A flaw within the Security Assertion Markup Language standard can be exploited to enable hackers to pose as someone else

Blackboard / Shutterstock

Attackers can manipulate a flaw within single-sign-on (SSO) systems to log in as another account user, Duo Security has disclosed.

Vulnerabilities in various libraries’ handling of Security Assertion Markup Language (SAML) can be modified to allow an attacker to pretend to be someone else.

This is according to Duo researcher Kelby Ludwig, who recently exposed the vulnerability in the Duo Network Gateway.

According to the report, OneLogin’s python-saml and ruby-saml, Clever’s saml2-js, the OmniAuth-SAML, and the Shibboleth openSAML C++ SSO toolkits were also affected by the bug.

Ludwig explained that a remote attacker could modify the SAML content without invalidating the cryptographic signature which is needed for authentication.

This means that a hacker could modify the user ID to make it appear as though they are using another person’s account without knowing their password.

Ludwig did add that an attacker would have to have a log-in in order to access the SAML in the first place.

He noted: “Exploitation of the bug is very simple. It just requires intercepting the SAML message and changing seven characters.”

While posing as another user may not seem particularly dangerous, Ludwig added that it could enable hackers to easily change access from a low-level user to an administrator.


##
##
