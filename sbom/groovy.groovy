sbom-stage.groovy
stage("Generate Software Bill of Materials (sbom) with Syft"){
    steps{
        sh '''
            curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
            syft app:${BUILD_NUMBER} --scope all-layers -o json > sbom-${BUILD_NUMBER}.json
            syft app:${BUILD_NUMBER} --scope all-layers -o table > sbom-${BUILD_NUMBER}.txt
        '''
    }
}


//
//
//
//
//
//
https://github.com/CycloneDX/cyclonedx-gradle-plugin
//
//
//

How to create SBOMs in Java with Maven and Gradle
Written by:
Brian Vermeer
Brian Vermeer
wordpress-sync/blog-hero-software-supply-chain-security
October 31, 2022

9 mins read
When building applications in Java, we highly depend on external libraries and frameworks. And each Java package that is imported likely also depends on more libraries. This means that the amount of Java packages included in your application is often not really transparent. As a developer, these nested (transitive) dependencies create the problem that you probably do not know all the libraries you are actually using.

Recently, we discussed why and how we should maintain our dependencies carefully. In the article Best practices for managing Java dependencies, I discussed the options and tools available for setting up a dependency management strategy. But what if you deliver your Java application to a customer? How do they know what dependencies are included? More importantly, how can they check if the dependencies are not vulnerable to security issues? The answer is a software bill of materials.

What is an SBOM?
A software bill of materials, often abbreviated as SBOM, is a list of all software components used in an application. The SBOM is made up of third-party open-source libraries, vendor-provided packages, and first-party artifacts built by the organization. You can basically see it as the full list of ingredients for your applications.

But be careful to not confuse an SBOM with Maven's Bill Of Materials (BOM). In Maven, a BOM is a special kind of POM file where we can centralize dependencies for an application. In most cases, these dependencies work well together and should be used as a set, like we see in BOMs used in Spring.

An SBOM is something you create next to your application, so any user or client has a uniform way to find out what your application is using under the hood.

Why should I create an SBOM?
There are multiple reasons for creating an SBOM. First of all, you create transparency about what how your application is containing. In most Java applications, 80% to 90% of the produced binary consists of other Java packages like libraries and frameworks.

Nowadays, we see a lot of security issues in the supply chain. The dependencies you use are part of your supply chain, so if a problem is found in one of these libraries, you need to know if an application is vulnerable. Take the recent Log4Shell and Spring4Shell vulnerabilities where certain commonly-used packages were compromised. When an SBOM is provided as part of every release, end users and clients can easily check if vulnerabilities impact them.

The creation of SBOMs is expected to be something that will be common practice, or sometimes even mandatory, when you deliver software. Therefore we feel it is important to cover how to create these SBOMs for your Java project, which we cover in the remainder of this article.

SBOM standards: SPDX and CycloneDX
Currently, there are multiple standards for SBOMs. The two most commonly used are SPDX and CycloneDX. Both of these standards provide a way to show the components your application contains.

The Software Package Data Exchange (SPDX) is a Linux Foundation collaborative project that provides an open standard for communicating software bill of material information, including provenance, licensing, security, and other related information. The SPDX specification is recognized as the international open standard for security, license compliance, and other software supply chain artifacts as ISO/IEC 5962:2021.

CycloneDX is a SBOM standard from the OWASP foundation designed for application security contexts and supply chain component analysis, providing an inventory of all first-party and third-party software components. The specification is rich and extends beyond software libraries to standards such as software as a service bill of materials (SaaSBOM), Vulnerability Exploitability Exchange (VEX), and more. The CycloneDX project provides standards in XML, JSON, and Protocol Buffers, as well as a large collection of official and community-supported tools that create or interoperate with the standard.

When to create an SBOM in Java
Java is a compiled language, so you should create an SBOM whenever you build a release version of your application. Therefore, creating an SBOM when using one of the Java build systems makes a lot of sense, since your build system downloads all the packages you need to compile and build your application. By using a plugin for Maven or Gradle, you can easily create SBOMs with every release of your binary either on a single machine or as part of your CI pipeline

Creating a Java SBOM with Maven
CycloneDX plugin for Maven
There is a CylconeDX plugin available on Maven central and Github that appears to be well-maintained and commonly used.

<plugins>
   <plugin>
       <groupId>org.cyclonedx</groupId>
       <artifactId>cyclonedx-maven-plugin</artifactId>
       <version>2.7.1</version>
       <executions>
           <execution>
               <phase>package</phase>
               <goals>
                   <goal>makeAggregateBom</goal>
               </goals>
           </execution>
       </executions>
       <configuration>
           <projectType>library</projectType>
           <schemaVersion>1.4</schemaVersion>
           <includeBomSerialNumber>true</includeBomSerialNumber>
           <includeCompileScope>true</includeCompileScope>
           <includeProvidedScope>true</includeProvidedScope>
           <includeRuntimeScope>true</includeRuntimeScope>
           <includeSystemScope>true</includeSystemScope>
           <includeTestScope>false</includeTestScope>
           <includeLicenseText>false</includeLicenseText>
           <outputReactorProjects>true</outputReactorProjects>
           <outputFormat>all</outputFormat>
           <outputName>CycloneDX-Sbom</outputName>
       </configuration>
   </plugin>
</plugins>
You can configure the CycloneDX plugin in different ways. In this case, I bound the makeAggregateBom goal of the plugin to the package phase of Maven. After my JAR is created, the plugin will create an SBOM, taking aggregation into account. It excludes the test dependencies and releases the SBOM in both XML and JSON format in my target folder.

All dependencies, both direct and transitive, are mentioned in the SBOM individually like below. The jackson-databind package, in this case, was transitively included in my application via sprint-boot-starter-web.

<component type="library" bom-ref="pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4?type=jar">
 <publisher>FasterXML</publisher>
 <group>com.fasterxml.jackson.core</group>
 <name>jackson-databind</name>
 <version>2.13.4</version>
 <description>General data-binding functionality for Jackson: works on core streaming API</description>
 <hashes>
   <hash alg="MD5">03cb7aea126610e4c96ca6d14d75cc55</hash>
   <hash alg="SHA-1">98b0edfa8e4084078f10b7b356c300ded4a71491</hash>
   <hash alg="SHA-256">c9faff420d9e2c7e1e4711dbeebec2506a32c9942027211c5c293d8d87807eb6</hash>
   <hash alg="SHA-512">23f32026b181c6c71efc7789a8420c7d5cbcfb15f7696657e75f9cbe3635d13a88634b5db3c344deb914b719d60e3a9bfc1b63fa23152394e1e70b8e7bcd2116</hash>
   <hash alg="SHA-384">e25e844575891b2f3bcb2fdc67ae9fadf54d2836052c9ea2c045f1375eaa97e4780cd6752bef0ebc658fa17400c55268</hash>
   <hash alg="SHA3-384">e6955877c2c27327f6814f06d681118be2ae1a36bc5ff2e84ad27f213203bf77c347ba18d9abc61d5f1c99b6e81f6c2d</hash>
   <hash alg="SHA3-256">88b12b0643a4791fa5cd0c5e30bc2631903870cf916c8a1b4198c856fd91e5f4</hash>
   <hash alg="SHA3-512">7e86a69bcf7b4c8a6949acce0ec15f33b74d5ac604f23cd631ec16bfdfd70d42499028b9d062648b31d7a187ea4dc98ec296a329f4cfd4952744ed1281fa9d9a</hash>
 </hashes>
 <licenses>
   <license>
     <id>Apache-2.0</id>
   </license>
 </licenses>
 <purl>pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4?type=jar</purl>
 <externalReferences><reference type="vcs"><url>http://github.com/FasterXML/jackson-databind</url></reference><reference type="website"><url>http://fasterxml.com/</url></reference><reference type="distribution"><url>https://oss.sonatype.org/service/local/staging/deploy/maven2/</url></reference></externalReferences>
</component>
SPDX plugin for Maven (prototype)
For SPDX, there is a Maven plugin as well. However, this is still marked as a prototype. In the example below, I used the latest version (at the time of writing) with a similar configuration as mentioned in the GitHub README. Additionally, I bound the SPDX creation task to the package phase, similar to the CycloneDX example.

<plugin>
   <groupId>org.spdx</groupId>
   <artifactId>spdx-maven-plugin</artifactId>
   <version>0.6.1</version>
   <executions>
       <execution>
           <id>build-spdx</id>
           <phase>package</phase>
           <goals>
               <goal>createSPDX</goal>
           </goals>
       </execution>
   </executions>
</plugin>
The output by default for this version of the plugin is located in /target/site/{groupId}_{artifactId}-{version}.spdx.json. As the file extension already suggests, the default output is JSON.

Browsing through the output, it surprised me that it only contained the top-level dependencies and not the transitive. Now, this plugin is marked as a prototype, so that could be why. Additionally, I might be doing something wrong. However, reading the docs did not give me a clear hint.

SPDX CLI tool for Maven
Alternatively, there is command line tool available called spdx-sbom-generator. This CLI tool can generate SPDX SBOMs for many package managers, including Maven for Java applications. Gradle is currently not supported.

Calling this tool from the command line without any parameter in the root of my application creates an SBOM for me in the SPDX format. Other outputs like JSON are also supported by using a parameter.

./spdx-sbom-generator
This generated SBOM seems to have all transitive dependencies individually mentioned, as I assumed it should.

##### Package representing the jackson-databind

PackageName: jackson-databind
SPDXID: SPDXRef-Package-jackson-databind-2.13.4
PackageVersion: 2.13.4
PackageSupplier: Organization: jackson-databind
PackageDownloadLocation: https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind/2.13.4
FilesAnalyzed: false
PackageChecksum: SHA1: 7d03e73aa50d143b3ecbdea2c0c9e158e5ed8021
PackageHomePage: NOASSERTION
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
PackageLicenseComments: NOASSERTION
PackageComment: NOASSERTION

Relationship: SPDXRef-Package-jackson-databind-2.13.4 DEPENDS_ON SPDXRef-Package-jackson-annotations-2.13.4
Relationship: SPDXRef-Package-jackson-databind-2.13.4 DEPENDS_ON SPDXRef-Package-jackson-core-2.13.4
If you want to create SBOMs in the SPDX format I would suggest this tool over the prototype plugin.

Creating a Java SBOM with Gradle
Now let’s take a look at Gradle. While Gradle is less used than Maven, it is still used a substantial amount, and we can definitely say it is a well-adopted build tool in the ecosystem.

CycloneDX for Gradle
There is a CyconeDX plugin available for Gradle. Just like the Maven plugin we discussed earlier, the Gradle plugin is released by the CycloneDX organization on Github with some of the same maintainers as the Maven plugin.

To use the plugin just add it to your plugin block in your Gradle file:

plugins {
   id 'org.cyclonedx.bom' version '1.7.2'
}
You can configure the plugin with a cyclonedxBom block like below:

cyclonedxBom {
   includeConfigs = ["runtimeClasspath"]
   skipConfigs = ["compileClasspath", "testCompileClasspath"]
   projectType = "application"
   schemaVersion = "1.4"
   destination = file("build/reports")
   outputName = "CycloneDX-Sbom"
   outputFormat = "all"
   includeBomSerialNumber = true
   componentVersion = "2.0.0"
}
In this example, I also added the line build.finalizedBy('cyclonedxBom') at the end of my Gradle file. Now it will automatically call the cyclonedxBom target after building my application and behave similarly to the Maven plugin. Obviously, this is up to you if and how you want to connect the plugin target.

The output is as expected and similar to what we have seen with the Maven plugin. With the configuration shown above, you will find both a JSON and an XML output of the SBOM in your project's build folder. So, this plugin is an excellent option for Gradle users to create SBOMs

SPDX for Gradle
Unfortunately, we could not find a real plugin to create SPDX-type SBOMs for Gradle projects. Also, third-party CLI tools are either not available or are not correctly working for Gradle-based Java projects. So, for now, there is no easy way to generate SPDX SBOMs for Gradle.

Creating SBOMs for your Java projects
Building an SBOM when you are building your Java project seems like a practice that will get more popular soon. Letting your build system take care of this makes a lot of sense.

For both Maven and Gradle, plugins are available that create the SBOMs when building your application. Creating SBOMs together with your Java build artifacts is straightforward using these plugins, as we showed above.
