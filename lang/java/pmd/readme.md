To use PMD to scan for security flaws in a Java Spring repository that you have stored locally, you can follow the steps below:

Install PMD on your local machine. You can download the latest version of PMD from the official website (https://pmd.github.io/). 
Once you have downloaded the binary distribution, extract the archive to a directory of your choice.

Navigate to the directory where you have stored your Java Spring repository.

Open a command prompt or terminal window and navigate to the bin directory within the PMD directory that you extracted earlier.

Run the following command to scan your Java Spring repository:

```
pmd.bat -d <path-to-your-java-spring-repo> -R rulesets/java/security.xml
```

Note: If you are using a Unix-based system, you can use the following command instead:

```
./pmd.sh -d <path-to-your-java-spring-repo> -R rulesets/java/security.xml
```

PMD will then scan your Java Spring repository and generate a report highlighting any security flaws it detects. The report will be displayed in the command prompt or terminal window.

You can also generate a report in HTML format by adding the following command-line option:

```
-r <path-to-report-file>
```

For example:

```
pmd.bat -d <path-to-your-java-spring-repo> -R rulesets/java/security.xml -r report.html
```

This will generate an HTML report named "report.html" in the current directory.

That's it! 
You have now used PMD to scan your Java Spring repository for security flaws.

###
###


Get started with Spring 5 and Spring Boot 2, through the Learn Spring course:
>> CHECK OUT THE COURSE
1. Overview
Simply put, PMD is a source code analyzer to find common programming flaws like unused variables, empty catch blocks, unnecessary object creation, and so forth.

It supports Java, JavaScript, Salesforce.com Apex, PLSQL, Apache Velocity, XML, XSL.

In this article, we'll focus on how to use PMD to perform static analysis in a Java project.

2. Prerequisites
Let's start with setting up PMD into a Maven project – using and configuring the maven-pmd-plugin:

<project>
    ...
    <reporting>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-pmd-plugin</artifactId>
                <version>3.7</version>
                <configuration>
                    <rulesets>
                        <ruleset>/rulesets/java/braces.xml</ruleset>
                        <ruleset>/rulesets/java/naming.xml</ruleset>
                    </rulesets>
                </configuration>
            </plugin>
        </plugins>
    </reporting>
</project>
Copy
You can find the latest version of maven-pmd-plugin here.

Notice how we're adding rulesets in the configuration here – these are a relative path to already define rules from the PMD core library.

Finally, before running everything, let's create a simple Java class with some glaring issues – something that PMD can start reporting problems on:

public class Ct {

    public int d(int a, int b) {
        if (b == 0)
            return Integer.MAX_VALUE;
        else
            return a / b;
    }
}
Copy
3. Run PMD
With the simple PMD config and the sample code – let's generate a report in the build target folder:

mvn site
Copy
The generated report is called pmd.html and is located in the target/site folder:

Files

com/baeldung/pmd/Cnt.java

Violation                                                                             Line

Avoid short class names like Cnt                                   1–10 
Avoid using short method names                                  3 
Avoid variables with short names like b                        3 
Avoid variables with short names like a                        3 
Avoid using if...else statements without curly braces 5 
Avoid using if...else statements without curly braces 7 
Copy
As you can see – we're not getting results. The report shows violations and line numbers in your Java code, according to PMD.

4. Rulesets
The PMD plugin uses five default rulesets:

basic.xml
empty.xml
imports.xml
unnecessary.xml
unusedcode.xml
You may use other rulesets or create your own rulesets, and configure these in the plugin:

<project>
    ...
    <reporting>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-pmd-plugin</artifactId>
                <version>3.7</version>
                <configuration>
                    <rulesets>
                        <ruleset>/rulesets/java/braces.xml</ruleset>
                        <ruleset>/rulesets/java/naming.xml</ruleset>
                        <ruleset>/usr/pmd/rulesets/strings.xml</ruleset>
                        <ruleset>http://localhost/design.xml</ruleset>
                    </rulesets>
                </configuration>
            </plugin>
        </plugins>
    </reporting>
</project>
Copy
Notice that we're using either a relative address, an absolute address or even a URL – as the value of the ‘ruleset' value in configuration.

A clean strategy for customizing which rules to use for a project is to write a custom ruleset file. In this file, we can define which rules to use, add custom rules, and customize which rules to include/exclude from the official rulesets.

5. Custom Ruleset
Let's now choose the specific rules we want to use from existing sets of rules in PMD – and let's also customize them.

First, we'll create a new ruleset.xml file. We can, of course, use one of the existing rulesets files as an example and copy and paste that into our new file, delete all the old rules from it, and change the name and description:

<?xml version="1.0"?>
<ruleset name="Custom ruleset"
  xmlns="http://pmd.sourceforge.net/ruleset/2.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://pmd.sourceforge.net/ruleset/2.0.0
  http://pmd.sourceforge.net/ruleset_2_0_0.xsd">
    <description>
        This ruleset checks my code for bad stuff
    </description>
</ruleset>
Copy
Secondly, let's add some rule references:

<!-- We'll use the entire 'strings' ruleset -->
<rule ref="rulesets/java/strings.xml"/>
Copy
Or add some specific rules:

<rule ref="rulesets/java/unusedcode.xml/UnusedLocalVariable"/>
<rule ref="rulesets/java/unusedcode.xml/UnusedPrivateField"/>
<rule ref="rulesets/java/imports.xml/DuplicateImports"/>
<rule ref="rulesets/java/basic.xml/UnnecessaryConversionTemporary"/>
Copy
We can customize the message and priority of the rule:

<rule ref="rulesets/java/basic.xml/EmptyCatchBlock"
  message="Must handle exceptions">
    <priority>2</priority>
</rule>
Copy
And you also can customize a rule's property value like this:

<rule ref="rulesets/java/codesize.xml/CyclomaticComplexity">
    <properties>
        <property name="reportLevel" value="5"/>
    </properties>
</rule>
Copy
Notice that you can customize individual referenced rules. Everything but the class of the rule can be overridden in your custom ruleset.

Next – you can also excluding rules from a ruleset:

<rule ref="rulesets/java/braces.xml">
    <exclude name="WhileLoopsMustUseBraces"/>
    <exclude name="IfElseStmtsMustUseBraces"/>
</rule>
Copy
Next – you can also exclude files from a ruleset using exclude patterns, with an optional overriding include pattern.

A file will be excluded from processing when there is a matching exclude pattern, but no matching include pattern.

Path separators in the source file path are normalized to be the ‘/’ character, so the same ruleset can be used on multiple platforms transparently.

Additionally, this exclude/include technique works regardless of how PMD is used (e.g. command line, IDE, Ant), making it easier to keep the application of your PMD rules consistent throughout your environment.

Here's a quick example:

<?xml version="1.0"?>
<ruleset ...>
    <description>My ruleset</description>
    <exclude-pattern>.*/some/package/.*</exclude-pattern>
    <exclude-pattern>
       .*/some/other/package/FunkyClassNamePrefix.*
    </exclude-pattern>
    <include-pattern>.*/some/package/ButNotThisClass.*</include-pattern>
    <rule>...
</ruleset>



6. Conclusion
In this quick article, we introduced PMD – a flexible and highly configurable tool focused on static analysis of Java code

As always, the full code presented in this tutorial is available over on Github.
