Trusting SBOMs in the Software Supply Chain: Syft Now Creates Attestations Using Sigstore
By: Dan Luhring
Mar 02, 2022
5 min read
Syft now creates attestations using sigstore hero image

##
#
https://anchore.com/sbom/creating-sbom-attestations-using-syft-and-sigstore/
#
##


With the recent release of Syft v0.40.0, you can now create signed SBOM attestations directly in Syft. This is made possible by Project Sigstore, which makes signing and verification of software artifacts insanely easy.
Why do attestations matter for SBOMs?

Attestations help users to validate that an SBOM comes from a trusted source in the software supply chain. As an example, I may use a container image without knowing all the software components or dependencies that are included in that image. However, if I trust whatever the producer of the container image says about what software is present, I can use the producer’s attestation to rely on that SBOM. This means that I can proceed to use the SBOM safely in my workflow in place of having done the analysis myself.
What is an attestation?

An attestation is a cryptographically signed “statement” that claims something (a “predicate”) is true about another thing (a “subject”).

In the container example above, the SBOM is the predicate and the container image is the subject, which means that the “signer” is attesting that the SBOM is an accurate representation of the contents of the container image.

The fact that this statement is signed means that consumers of this data can decide for themselves whether or not they trust the statement based on their trust of the identity (a public key, a person, a company, or some other entity) that did the signing. It also means that consumers can detect if the data they’re ingesting has been tampered with since the attestation was created.

The “statement” concept is extremely versatile because the subject can be anything someone is interested in: a commit in a repository, an executable file, a container image, and so on. And the predicate can describe anything about the subject: a code review, information on where the subject originally came from, or what software packages compose the subject, to name just a few examples.
Why was attestation added to Syft?

Syft gathers data that’s used in downstream security analysis (like vulnerability scanning), so it’s important that you have ways to safely rely on SBOM data, especially when SBOMs cross organizational boundaries. Thanks to tools like Sigstore’s Cosign, it has become incredibly easy to publish trusted data for other people to use.

Syft had already been able to produce SBOMs that could then be consumed in Cosign-based workflows (both Syft and Cosign support SBOMs in CycloneDX, SPDX, and Syft’s native format), but by bringing attestation closer to the point of data generation (directly in Syft’s execution), Syft enables a safer creation of trusted information because the statement (which includes the SBOM, itself) is signed before any data is exposed beyond the Syft process. This means there’s no chance for anyone to sneak changes into the SBOM before it gets sealed in the attestation.

How to create SBOM attestations using Syft and Sigstore

On top of that, the Syft and Cosign integration makes it easier to create SBOM attestations now that it’s just one command from a single tool.
How to create SBOM attestations with Syft

To create an SBOM attestation in Syft, just use the new `attest` command. Syft uses in-toto attestations, which is a particular framework and specification for creating and using attestations. In one fell swoop, Syft will generate an SBOM for the specified target and create an in-toto attestation for that SBOM, using Cosign’s library internally to generate and sign the in-toto statement.

1. If you don’t have a Cosign key pair, generate one.

$ cosign generate-key-pair

Note: Your private key is encrypted with a password. When you’re generating the key pair, you can store a password in the `COSIGN_PASSWORD` environment variable to get prompted by Cosign. Additionally, if you’ve already stored your password in `COSIGN_PASSWORD`, Syft will find this password and won’t need to ask you for it when signing the SBOM attestation.

2. To create the SBOM attestation and write the attestation to a file, use `syft attest` with a file redirect. (Note that aside from the `–key` argument, `syft attest <image>` just uses the same syntax as `syft <image>`!)

$ syft attest --key ./cosign.key <my-image> -o cyclonedx-json > ./my-image-sbom.att.json

3. If you want, you can use Cosign to attach the attestation to an image in a container registry.

$ cosign attach attestation <my-image> --attestation ./my-image-sbom.att.json

Great! Now anyone who has your public key can use Cosign to verify your SBOM attestation, which means they can trust the SBOM’s representation of your container image.

$ cosign verify-attestation <my-image> --key ./cosign.pub

SBOM formats used for attestations

In-toto statements are flexible with the format of the predicate data (which is the SBOM, in this case). Statements declare the type of the predicate with a “predicateType” field. Since the statement is JSON data, the predicate data within the statement should also be JSON data.

Syft can create attestations with the CycloneDX JSON format, the SPDX JSON format, and with Syft’s own lossless JSON format. If you don’t specify a format, Syft defaults to its lossless JSON format.

Read more about Syft’s attestation workflow.
Looking ahead with Syft, Grype, and Sigstore

We plan to integrate Syft more deeply with Sigstore in the coming months, starting by adding support for Sigstore’s “keyless workflow,” which eliminates the need for users to manage their own key pairs.

We also plan to extend attestation support into Grype to enable vulnerability scans based on trusted SBOM analysis and to provide attestations for vulnerability scans. We view attestations as a significant enhancement to the existing security workflows of the Syft and Grype ecosystem.

Be sure to grab the latest release of Syft and try out SBOM attestation for yourself!
Shout-outs <3

Big thanks to Chris Phillips for the engineering work to make this integration happen. Thanks to Santiago Torres-Arias for expert guidance on using the in-toto attestation framework. And thanks to Jake Sanders and Matt Moore for helping to make Cosign integration more accessible for other projects.
