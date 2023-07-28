
> Static program analysis is the analysis of computer software that is performed without actually executing programs — [Wikipedia](https://en.wikipedia.org/wiki/Static_program_analysis)

This is a collection of static analysis tools and code quality checkers. Pull requests are very welcome!  
**Note: :copyright: stands for proprietary software. All other tools are Open Source.**  

# Table of Contents

- [Programming Languages](#programming-languages)
- [Multiple languages](#multiple-languages)
- [Other](#other)
  - [Build tools](#build-tools)
  - [Binaries](#binaries)
  - [Containers](#containers)
  - [Config Files](#config-files)
  - [Configuration Management](#configuration-management)
  - [CSS](#css)
  - [HTML](#html)
  - [IDE Plugins](#ide-plugins)
  - [LaTeX](#latex)
  - [Makefiles](#makefiles)
  - [Markdown](#markdown)
  - [Mobile](#mobile)
  - [Packages](#packages)
  - [Template Languages](#template-languages)
  - [Translation](#translation)
  - [Web services](#web-services)
  - [Writing](#writing)
- [More Collections](#more-collections)


# Programming Languages

## Ada

* [Codepeer](http://www.adacore.com/codepeer) - detects run-time and logic errors
* [Polyspace for Ada](https://www.mathworks.com/products/polyspace-ada.html) :copyright: - provide code verification that proves the absence of overflow, divide-by-zero, out-of-bounds array access, and certain other run-time errors in source code.
* [Understand](https://scitools.com/ada-programming-essential/) :copyright: - IDE that provides code analysis, standards testing, metrics, graphing, dependency analysis and more for Ada and VHDL.

## Awk

* [gawk --lint](https://www.gnu.org/software/gawk/manual/html_node/Options.html) - warns about constructs that are dubious or nonportable to other awk implementations.

## C/C++

* [clang-tidy](http://clang.llvm.org/extra/clang-tidy/) - clang static analyser
* [CMetrics](https://github.com/MetricsGrimoire/CMetrics) - Measures size and complexity for C files
* [CodeSonar from GrammaTech](https://www.grammatech.com/products/codesonar) :copyright: - Advanced, whole program, deep path, static analysis of C and C++ with easy-to-understand explanations and code and path visualization.
* [Corrode](https://github.com/jameysharp/corrode) - Semi-automatic translation from C to Rust. Could reveal bugs in the original implementation by showing Rust compiler warnings and errors.
* [cppcheck](https://github.com/danmar/cppcheck) - static analysis of C/C++ code
* [cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint) - automated C++ checker that follows Google's style guide
* [cqmetrics](https://github.com/dspinellis/cqmetrics) - quality metrics for C code
* [CScout](https://www.spinellis.gr/cscout/) - complexity and quality metrics for for C and C preprocessor code
* [flawfinder](http://www.dwheeler.com/flawfinder/) - finds possible security weaknesses
* [flint++](http://l2program.co.uk/category/flint) - cross-platform, zero-dependency port of flint, a lint program for C++ developed and used at Facebook.
* [Frama-C](http://frama-c.com/) - a sound and extensible static analyzer for C code
* [oclint](http://oclint.org/) - static analysis of C/C++ code
* [Polyspace Bug Finder](https://www.mathworks.com/products/polyspace-bug-finder.html) :copyright: - identifies run-time errors, concurrency issues, security vulnerabilities, and other defects in C and C++ embedded software.
* [Polyspace Code Prover](https://www.mathworks.com/products/polyspace-code-prover.html) :copyright: - provide code verification that proves the absence of overflow, divide-by-zero, out-of-bounds array access, and certain other run-time errors in C and C++ source code.
* [scan-build](https://clang-analyzer.llvm.org/scan-build.html) - Analyzes C/C++ code using LLVM at compile-time
* [splint](https://github.com/ravenexp/splint) - Annotation-assisted static program checker
* [tis-interpreter](https://github.com/TrustInSoft/tis-interpreter) - An interpreter for finding subtle bugs in programs written in standard C
* [vera++](https://bitbucket.org/verateam/vera/wiki/Introduction) - Vera++ is a programmable tool for verification, analysis and transformation of C++ source code.

## C# #

* [.NET Analyzers](https://github.com/DotNetAnalyzers) - An organization for the development of analyzers (diagnostics and code fixes) using the .NET Compiler Platform.
* [Code Analysis Rule Collection](https://carc.codeplex.com/) - Contains a set of diagnostics, code fixes and refactorings built on the Microsoft .NET Compiler Platform "Roslyn".
* [code-cracker](https://github.com/code-cracker/code-cracker) - An analyzer library for C# and VB that uses Roslyn to produce refactorings, code analysis, and other niceties.
* [CodeRush](https://www.devexpress.com/products/coderush/) :copyright: - Code creation, debugging, navigation, refactoring, analysis and visualization tools that use the Roslyn engine in Visual Studio 2015 and up.
* [CSharpEssentials](https://github.com/DustinCampbell/CSharpEssentials) - C# Essentials is a collection of Roslyn diagnostic analyzers, code fixes and refactorings that make it easy to work with C# 6 language features.
* [Designite](http://www.designite-tools.com) :copyright: - Designite is a software design quality assessment tool. It supports detection of implementation and design smells, computation of various code quality metrics, and trend analysis.
* [Gendarme](http://www.mono-project.com/docs/tools+libraries/tools/gendarme/) - Gendarme inspects programs and libraries that contain code in ECMA CIL format (Mono and .NET).
* [NDepend](http://www.ndepend.com/) :copyright: - Measure, query and visualize your code and avoid unexpected issues, technical debt and complexity.
* [Puma Scan](https://github.com/pumasecurity/puma-scan) - Puma Scan provides real time secure code analysis for common vulnerabilities (XSS, SQLi, CSRF, LDAPi, crypto, deserialization, etc.) as development teams write code in Visual Studio.
* [Refactoring Essentials](http://vsrefactoringessentials.com/) - The free Visual Studio 2015 extension for C# and VB.NET refactorings, including code best practice analyzers.
* [ReSharper](https://www.jetbrains.com/resharper/) :copyright: - Extends Visual Studio with on-the-fly code inspections for C#, VB.NET, ASP.NET, JavaScript, TypeScript and other technologies.
* [Roslyn Security Guard](https://dotnet-security-guard.github.io/) - Project that focus on the identification of potential vulnerabilities such as SQL injection, cross-site scripting (XSS), CSRF, cryptography weaknesses, hardcoded passwords and many more.
* [SonarLint for Visual Studio](https://vs.sonarlint.org/) - SonarLint is an extension for Visual Studio 2015 and 2017 that provides on-the-fly feedback to developers on new bugs and quality issues injected into .NET code.
* [VSDiagnostics](https://github.com/Vannevelj/VSDiagnostics) - A collection of static analyzers based on Roslyn that integrate with VS.
* [Wintellect.Analyzers](https://github.com/Wintellect/Wintellect.Analyzers) - .NET Compiler Platform ("Roslyn") diagnostic analyzers and code fixes.

## Crystal

* [crystal](https://crystal-lang.org/) - The Crystal compiler has built-in linting functionality.

## Elixir

* [credo](https://github.com/rrrene/credo) - A static code analysis tool with a focus on code consistency and teaching.
* [Dogma](https://github.com/lpil/dogma) - A code style enforcer for Elixir
* [sobelow](https://github.com/nccgroup/sobelow) - Security-focused static analysis for the Phoenix Framework

## Erlang

* [elvis](https://github.com/inaka/elvis) - Erlang Style Reviewer

## Go

* [deadcode](https://github.com/tsenart/deadcode) - Finds unused code.
* [dingo-hunter](https://github.com/nickng/dingo-hunter) - Static analyser for finding deadlocks in Go.
* [dupl](https://github.com/mibk/dupl) - Reports potentially duplicated code.
* [errcheck](https://github.com/kisielk/errcheck) - Check that error return values are used.
* [flen](https://github.com/lafolle/flen) - Get info on length of functions in a Go package.
* [gas](https://github.com/GoASTScanner/gas) - Inspects source code for security problems by scanning the Go AST.
* [Go Meta Linter](https://github.com/alecthomas/gometalinter) - Concurrently run Go lint tools and normalise their output.
* [go tool vet --shadow](https://golang.org/cmd/vet/#hdr-Shadowed_variables) - Reports variables that may have been unintentionally shadowed.
* [go vet](https://golang.org/cmd/vet/) - Examines Go source code and reports suspicious.
* [go-staticcheck](https://github.com/dominikh/go-tools/tree/master/cmd/staticcheck) - go vet on steroids, similar to ReSharper for C#.
* [go/ast](https://golang.org/pkg/go/ast/) - Package ast declares the types used to represent syntax trees for Go packages.
* [goconst](https://github.com/jgautheron/goconst) - Finds repeated strings that could be replaced by a constant.
* [gocyclo](https://github.com/fzipp/gocyclo) - Calculate cyclomatic complexities of functions in Go source code.
* [gofmt -s](https://golang.org/cmd/gofmt/) - Checks if the code is properly formatted and could not be further simplified.
* [goimports](https://godoc.org/golang.org/x/tools/cmd/goimports) - Checks missing or unreferenced package imports.
* [golint](https://github.com/golang/lint) - Prints out coding style mistakes in Go source code.
* [goreporter](https://github.com/wgliang/goreporter) - concurrently runs many linters and normalises their output to a report.
* [goroutine-inspect](https://github.com/linuxerwang/goroutine-inspect) - An interactive tool to analyze Golang goroutine dump.
* [gosimple](https://github.com/dominikh/go-tools/tree/master/cmd/gosimple) - Report simplifications in code.
* [gotype](https://golang.org/x/tools/cmd/gotype) - Syntactic and semantic analysis similar to the Go compiler.
* [ineffassign](https://github.com/gordonklaus/ineffassign) - Detect ineffectual assignments in Go code
* [interfacer](https://github.com/mvdan/interfacer) - Suggest narrower interfaces that can be used.
* [lll](https://github.com/walle/lll) - Report long lines.
* [maligned](https://github.com/mdempsky/maligned) -  Detect structs that would take less memory if their fields were sorted.
* [megacheck](https://github.com/dominikh/go-tools/tree/master/cmd/megacheck) - Run staticcheck, gosimple and unused, sharing work.
* [misspell](https://github.com/client9/misspell) - Finds commonly misspelled English words.
* [nakedret](https://github.com/alexkohler/nakedret) - Finds naked returns.
* [prealloc](https://github.com/alexkohler/prealloc) - Finds slice declarations that could potentially be preallocated.
* [safesql](https://github.com/stripe/safesql) - Static analysis tool for Golang that protects against SQL injections.
* [structcheck](https://github.com/opennota/check) - Find unused struct fields.
* [test](http://golang.org/pkg/testing/) - Show location of test failures from the stdlib testing module.
* [testify](https://github.com/stretchr/testify) - Show location of failed testify assertions.
* [unconvert](https://github.com/mdempsky/unconvert) - Detect redundant type conversions.
* [unimport](https://github.com/alexkohler/unimport) - Finds unnecessary import aliases
* [unparam](https://github.com/mvdan/unparam) - Find unused function parameters.
* [unused](https://github.com/dominikh/go-tools/tree/master/cmd/unused) - Find unused variables.
* [varcheck](https://github.com/opennota/check) - Find unused global variables and constants.

## Groovy

* [CodeNarc](https://github.com/CodeNarc/CodeNarc) - a static analysis tool for Groovy source code, enabling monitoring and enforcement of many coding standards and best practices

## Haskell

* [HLint](https://github.com/ndmitchell/hlint) - HLint is a tool for suggesting possible improvements to Haskell code.

## Haxe

* [Haxe Checkstyle](https://github.com/HaxeCheckstyle/haxe-checkstyle) - A static analysis tool to help developers write Haxe code that adheres to a coding standard.

## Java
* [Checker Framework](https://github.com/typetools/checker-framework/) - Pluggable type-checking for Java http://checkerframework.org/
* [checkstyle](https://github.com/checkstyle/checkstyle) - checking Java source code for adherence to a Code Standard or set of validation rules (best practices)
* [ckjm](http://www.spinellis.gr/sw/ckjm/) - calculates Chidamber and Kemerer object-oriented metrics by processing the bytecode of compiled Java files
* [Error-prone](https://github.com/google/error-prone) - Catch common Java mistakes as compile-time errors
* [fb-contrib](https://github.com/mebigfatguy/fb-contrib) - A plugin for FindBugs with additional bug detectors
* [Find Security Bugs](https://find-sec-bugs.github.io/) - IDE/SonarQube plugin for security audits of Java web applications.
* [Findbugs](https://github.com/findbugsproject/findbugs) - FindBugs is a program to find bugs in Java programs. It looks for patterns are likely to be errors.
* [Hopper](https://github.com/cuplv/hopper) - A static analysis tool written in scala for languages that run on JVM
* [HuntBugs](https://github.com/amaembo/huntbugs) - Bytecode static analyzer tool based on Procyon Compiler Tools aimed to supersede FindBugs.
* [NullAway](https://github.com/uber/NullAway) - Type-based null-pointer checker with low build-time overhead; an [Error Prone](http://errorprone.info/) plugin
* [OWASP Dependency Check](https://www.owasp.org/index.php/OWASP_Dependency_Check) - Checks dependencies for known, publicly disclosed, vulnerabilities.
* [Spoon](https://github.com/INRIA/spoon) - Library to write your own static analyses and architectural rule checkers for Java. Can be integrated in Maven and Gradle.
* [SpotBugs](https://spotbugs.github.io/) - SpotBugs is FindBugs' successor. A tool for static analysis to look for bugs in Java code.

## JavaScript

* [aether](https://github.com/codecombat/aether) - Lint, analyze, normalize, transform, sandbox, run, step through, and visualize user JavaScript, in node or the browser.
* [ClosureLinter](https://github.com/google/closure-linter) - ensures that all of your project's JavaScript code follows the guidelines in the Google JavaScript Style Guide. It can also automatically fix many common errors
* [coffeelint](https://github.com/clutchski/coffeelint) - A style checker that helps keep CoffeeScript code clean and consistent.
* [complexity-report](https://github.com/jared-stilwell/complexity-report) - Software complexity analysis for JavaScript projects
* [DeepScan](https://deepscan.io) :copyright: - An analyzer for JavaScript which targets runtime errors and quality issues rather than coding conventions.
* [escomplex](https://github.com/jared-stilwell/escomplex) - Software complexity analysis of JavaScript-family abstract syntax trees.
* [eslint](https://github.com/eslint/eslint) - A fully pluggable tool for identifying and reporting on patterns in JavaScript
* [Esprima](https://github.com/jquery/esprima) - ECMAScript parsing infrastructure for multipurpose analysis
* [flow](https://flow.org/) - A static type checker for JavaScript.
* [jshint](https://github.com/jshint/jshint) - detect errors and potential problems in JavaScript code and enforce your team's coding conventions
* [JSLint](https://github.com/douglascrockford/JSLint) :copyright: - The JavaScript Code Quality Tool
* [plato](https://github.com/es-analysis/plato) - Visualize JavaScript source complexity
* [Prettier](https://github.com/prettier/prettier) - An opinionated code formatter.
* [quality](https://github.com/jden/quality) - zero configuration code and module linting
* [standard](http://standardjs.com/) - An npm module that checks for Javascript Styleguide issues
* [XO](https://github.com/sindresorhus/xo) - Enforce strict code style. Never discuss code style on a pull request again!
* [yardstick](https://github.com/calmh/yardstick) - Javascript code metrics

## Kotlin

* [detekt](https://github.com/arturbosch/detekt) - Static code analysis for Kotlin code.
* [ktlint](https://github.com/shyiko/ktlint) - An anti-bikeshedding Kotlin linter with built-in formatter

## Lua

* [luacheck](https://github.com/mpeterv/luacheck) - A tool for linting and static analysis of Lua code.

## MATLAB

* [mlint](https://de.mathworks.com/help/matlab/ref/mlint.html) :copyright: - Check MATLAB code files for possible problems.

## Perl

* [Perl::Critic](http://search.cpan.org/~thaljef/Perl-Critic-1.126/lib/Perl/Critic.pm) - Critique Perl source code for best-practices.

## PHP

* [dephpend](https://github.com/mihaeu/dephpend) - Dependency analysis tool
* [deptrac](https://github.com/sensiolabs-de/deptrac) - Enforce rules for dependencies between software layers.
* [DesignPatternDetector](https://github.com/Halleck45/DesignPatternDetector) - detection of design patterns in PHP code
* [EasyCodingStandard](https://github.com/Symplify/EasyCodingStandard) - combine [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer) and [PHP-CS-Fixer](https://github.com/FriendsOfPHP/PHP-CS-Fixer)
* [exakat](https://github.com/exakat/exakat) - An automated code reviewing engine for PHP
* [GrumPHP](https://github.com/phpro/grumphp) - checks code on every commit
* [Mondrian](https://github.com/Trismegiste/Mondrian) - a set of static analysis and refactoring tools which use graph theory
* [Parse](https://github.com/psecio/parse) - A Static Security Scanner
* [phan](https://github.com/etsy/phan) - a modern static analyzer from etsy
* [Php Inspections (EA Extended)](https://github.com/kalessil/phpinspectionsea) - A Static Code Analyzer for PHP.
* [PHP Refactoring Browser](https://github.com/QafooLabs/php-refactoring-browser) - Refactoring helper
* [PHP-Parser](https://github.com/nikic/PHP-Parser) - A PHP parser written in PHP
* [PHP-Token-Reflection](https://github.com/Andrewsville/PHP-Token-Reflection) - Library emulating the PHP internal reflection
* [php7cc](https://github.com/sstalle/php7cc) - PHP 7 Compatibility Checker
* [php7mar](https://github.com/Alexia/php7mar) - assist developers in porting their code quickly to PHP 7
* [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer) - detects violations of a defined set of coding standards
* [phpcpd](https://github.com/sebastianbergmann/phpcpd) - Copy/Paste Detector (CPD) for PHP code.
* [phpdcd](https://github.com/sebastianbergmann/phpdcd) - Dead Code Detector (DCD) for PHP code.
* [PhpDependencyAnalysis](https://github.com/mamuz/PhpDependencyAnalysis) - builds a dependency graph for a project
* [phpdoc-to-typehint](https://github.com/dunglas/phpdoc-to-typehint) - Add scalar type hints and return types to existing PHP projects using PHPDoc annotations
* [PHPMD](https://phpmd.org/) - finds possible bugs in your code
* [PhpMetrics](https://github.com/Halleck45/PhpMetrics) - calculates code complexity metrics
* [PHPQA](https://github.com/EdgedesignCZ/phpqa) - A tool for running QA tools (phploc, phpcpd, phpcs, pdepend, phpmd, phpmetrics)
* [phpqa](https://github.com/jmolivas/phpqa) - PHPQA all-in-one Analyzer CLI tool
* [phpsa](https://github.com/ovr/phpsa) - Static analysis tool for PHP.
* [PHPStan](https://github.com/phpstan/phpstan) - PHP Static Analysis Tool - discover bugs in your code without running it!
* [Progpilot](https://github.com/designsecurity/progpilot) - A static analysis tool for security purposes
* [Psalm](https://github.com/vimeo/psalm) - Static analysis tool for finding errors in PHP applications
* [RIPS](https://github.com/ripsscanner/rips) - A static source code analyser for vulnerabilities in PHP scripts
* [Tuli](https://github.com/ircmaxell/Tuli) - A static analysis engine
* [twig-lint](https://github.com/asm89/twig-lint) - twig-lint is a lint tool for your twig files.
* [WAP](https://www.owasp.org/index.php/OWASP_WAP-Web_Application_Protection) - Tool to detect and correct input validation vulnerabilities in PHP (4.0 or higher) web applications and predicts false positives by combining static analysis and data mining.

## Python

* [bandit](https://github.com/openstack/bandit) - a tool to find common security issues in Python code
* [jedi](https://github.com/davidhalter/jedi) - autocompletion/static analysis library for Python
* [linty fresh](https://github.com/lyft/linty_fresh) - parse lint errors and report them to Github as comments on a pull request
* [mccabe](https://github.com/PyCQA/mccabe) - check McCabe complexity
* [mypy](https://github.com/python/mypy) - an experimental optional static type checker for Python that aims to combine the benefits of dynamic (or "duck") typing and static typing
* [py-find-injection](https://github.com/uber/py-find-injection) - find SQL injection vulnerabilities in Python code
* [pycodestyle](https://github.com/PyCQA/pycodestyle) - (formerly `pep8`) check Python code against some of the style conventions in PEP 8
* [pydocstyle](https://github.com/PyCQA/pydocstyle) - check compliance with Python docstring conventions
* [pyflakes](https://github.com/pyflakes/pyflakes/) - check Python source files for errors
* [pylint](https://github.com/PyCQA/pylint) - looks for programming errors, helps enforcing a coding standard and sniffs for some code smells. It additionally includes `pyreverse` (an UML diagram generator) and `symilar` (a similarities checker).
* [pyroma](https://github.com/regebro/pyroma) - rate how well a Python project complies with the best practices of the Python packaging ecosystem, and list issues that could be improved
* [PyT - Python Taint](https://github.com/python-security/pyt) - A static analysis tool for detecting security vulnerabilities in Python web applications.
* [vulture](https://github.com/jendrikseipp/vulture) - find unused classes, functions and variables in Python code
* [xenon](https://github.com/rubik/xenon) - monitor code complexity using [`radon`](https://github.com/rubik/radon)

## Python wrappers

* [ciocheck](https://github.com/ContinuumIO/ciocheck) - linter, formatter and test suite helper. As a linter, it is a wrapper around `pep8`, `pydocstyle`, `flake8`, and `pylint`.
* [flake8](https://github.com/PyCQA/flake8) - a wrapper around `pyflakes`, `pycodestyle` and `mccabe`
* [prospector](https://github.com/landscapeio/prospector) - a wrapper around `pylint`, `pep8`, `mccabe` and others

## R

* [lintr](https://github.com/jimhester/lintr) :copyright: - Static Code Analysis for R

## Ruby

* [brakeman](https://github.com/presidentbeef/brakeman) - A static analysis security vulnerability scanner for Ruby on Rails applications
* [cane](https://github.com/square/cane) - Code quality threshold checking as part of your build
* [dawnscanner](https://github.com/thesp0nge/dawnscanner) - a static analysis security scanner for ruby written web applications. It supports Sinatra, Padrino and Ruby on Rails frameworks.
* [flay](https://github.com/seattlerb/flay) - Flay analyzes code for structural similarities.
* [flog](https://github.com/seattlerb/flog) - Flog reports the most tortured code in an easy to read pain report. The higher the score, the more pain the code is in.
* [laser](https://github.com/michaeledgar/laser) - Static analysis and style linter for Ruby code.
* [pelusa](https://github.com/codegram/pelusa) - Static analysis Lint-type tool to improve your OO Ruby code
* [quality](https://github.com/apiology/quality) - Runs quality checks on your code using community tools, and makes sure your numbers don't get any worse over time.
* [reek](https://github.com/troessner/reek) - Code smell detector for Ruby
* [rubocop](https://github.com/bbatsov/rubocop) - A Ruby static code analyzer, based on the community Ruby style guide.
* [Rubrowser](https://github.com/blazeeboy/rubrowser) - Ruby classes interactive dependency graph generator.
* [ruby-lint](https://github.com/YorickPeterse/ruby-lint) - Static code analysis for Ruby
* [rubycritic](https://github.com/whitesmith/rubycritic) - A Ruby code quality reporter
* [SandiMeter](https://github.com/makaroni4/sandi_meter) - Static analysis tool for checking Ruby code for Sandi Metz' rules.

## Rust

* [clippy](https://github.com/Manishearth/rust-clippy) - a code linter to catch common mistakes and improve your Rust code
* [electrolysis](https://github.com/Kha/electrolysis) - A tool for formally verifying Rust programs by transpiling them into definitions in the Lean theorem prover.
* [herbie](https://github.com/mcarton/rust-herbie-lint) - Adds warnings or errors to your crate when using a numerically unstable floating point expression.
* [linter-rust](https://github.com/AtomLinter/linter-rust) - Linting your Rust-files in Atom, using rustc and cargo
* [Rust Language Server](https://github.com/rust-lang-nursery/rls) - Supports functionality such as 'goto definition', symbol search, reformatting, and code completion, and enables renaming and refactorings.
* [rustfix](https://github.com/killercup/rustfix) - read and apply the suggestions made by rustc (and third-party lints, like those offered by clippy).

## Scala

* [linter](https://github.com/HairyFotr/linter) - Linter is a Scala static analysis compiler plugin which adds compile-time checks for various possible bugs, inefficiencies, and style problems.
* [Scalastyle](http://www.scalastyle.org) - Scalastyle examines your Scala code and indicates potential problems with it.
* [scapegoat](https://github.com/sksamuel/scapegoat) - Scala compiler plugin for static code analysis
* [WartRemover](https://github.com/puffnfresh/wartremover) - a flexible Scala code linting tool.

## Shell

* [shellcheck](https://github.com/koalaman/shellcheck) - ShellCheck, a static analysis tool that gives warnings and suggestions for bash/sh shell scripts

## SQL

* [sqlcheck](https://github.com/jarulraj/sqlcheck) - Automatically identify anti-patterns in SQL queries
* [sqlint](https://github.com/purcell/sqlint) - Simple SQL linter

## Swift

* [SwiftLint](https://github.com/realm/SwiftLint) - A tool to enforce Swift style and conventions
* [Tailor](https://github.com/sleekbyte/tailor) - A static analysis and lint tool for source code written in Apple's Swift programming language.

## TypeScript

* [Codelyzer](https://github.com/mgechev/codelyzer) - A set of tslint rules for static code analysis of Angular 2 TypeScript projects.
* [TSLint](https://github.com/palantir/tslint) - An extensible linter for the TypeScript language.
* [tslint-microsoft-contrib](https://github.com/Microsoft/tslint-microsoft-contrib) - A set of tslint rules for static code analysis of TypeScript projects maintained by Microsoft.

# Multiple languages

* [AppChecker](https://npo-echelon.ru/en/solutions/appchecker.php) :copyright: - Static analysis for C/C++/C#, PHP and Java
* [Application Inspector](https://www.ptsecurity.com/ww-en/products/ai/) :copyright: - Combined SAST, DAST, IAST security scanner for C#, PHP, Java, SQL languages
* [APPscreener](https://appscreener.us) :copyright: - Static code analysis for binary and source code - Java/Scala, PHP, Javascript, C#, PL/SQL, Python, T-SQL, C/C++, ObjectiveC/Swift, Visual Basic 6.0, Ruby, Delphi, ABAP, HTML5 and Solidity
* [Axivion Bauhaus Suite](https://www.axivion.com/en/products-services-9#products_bauhaussuite) :copyright: - Tracks down error-prone code locations, style violations, cloned or dead code, cyclic dependencies and more for C/C++, C#/.NET, Java and Ada 83/Ada 95
* [coala](https://coala.io/) - Language independent framework for creating code analysis - supports [over 60 languages](https://coala.io/languages) by default
* [Cobra](http://spinroot.com/cobra/) :copyright: - Structural source code analyzer by NASA's Jet Propulsion Laboratory. Supports C, C++, Ada, and Python.
* [codeburner](https://github.com/groupon/codeburner) - Provides a unified interface to sort and act on the issues it finds
* [CodeFactor](https://codefactor.io) :copyright: - Static Code Analysis for C#, C, C++, CoffeeScript, CSS, Groovy, GO, JAVA, JavaScript, Less, Python, Ruby, Scala, SCSS, TypeScript.
* [Coverity Save](http://www.coverity.com/products/coverity-save/) :copyright: - Static analysis for  C/C++, Java and C#
* [cqc](https://github.com/xcatliu/cqc) - Check your code quality for js, jsx, vue, css, less, scss, sass and styl files.
* [DevSkim](https://github.com/microsoft/devskim) - Regex-based static analysis tool for Visual Studio, VS Code, and Sublime Text - C/C++, C#, PHP, ASP, Python, Ruby, Java, and others.
* [graudit](https://github.com/wireghoul/graudit) - Grep rough audit - source code auditing tool - C/C++, PHP, ASP, C#, Java, Perl, Python, Ruby
* [Hound CI](https://houndci.com/) - Comments on style violations in GitHub pull requests. Supports Coffeescript, Go, HAML, JavaScript, Ruby, SCSS and Swift.
* [imhotep](https://github.com/justinabrahms/imhotep) - Comment on commits coming into your repository and check for syntactic errors and general lint warnings.
* [Infer](https://github.com/facebook/infer) - A static analyzer for Java, C and Objective-C
* [Klocwork](http://www.klocwork.com/products-services/klocwork) :copyright: - Quality and Security Static analysis for  C/C++, Java and C#
* [oclint](https://github.com/oclint/oclint) - A static source code analysis tool to improve quality and reduce defects for C, C++ and Objective-C
* [pfff](https://github.com/facebook/pfff) - Facebook's tools for code analysis, visualizations, or style-preserving source transformation for many languages
* [PMD](https://pmd.github.io/) - A source code analyzer for Java, Javascript, PLSQL, XML, XSL and others
* [pre-commit](https://github.com/pre-commit/pre-commit) - A framework for managing and maintaining multi-language pre-commit hooks.
* [PVS-Studio](https://www.viva64.com/en/pvs-studio/) :copyright: - a ([conditionaly free](https://www.viva64.com/en/b/0457/) for FOSS) static analysis of C/C++ and C# code. For advertising purposes [you can propose a large FOSS project for analysis by PVS employees](https://github.com/viva64/pvs-studio-check-list).
* [shipshape](https://github.com/google/shipshape) - Static program analysis platform that allows custom analyzers to plug in through a common interface
* [SonarQube](http://www.sonarqube.org/) - SonarQube is an open platform to manage code quality.
* [STOKE](https://github.com/StanfordPL/stoke) - a programming-language agnostic stochastic optimizer for the x86_64 instruction set. It uses random search to explore the extremely high-dimensional space of all possible program transformations
* [Undebt](https://github.com/Yelp/undebt) - Language-independent tool for massive, automatic, programmable refactoring based on simple pattern definitions
* [WALA](http://wala.sourceforge.net/wiki/index.php/Main_Page) - static analysis capabilities for Java bytecode and related languages and for JavaScript
* [XCode](https://developer.apple.com/xcode/) :copyright: - XCode provides a pretty decent UI for [Clang's](http://clang-analyzer.llvm.org/xcode.html) static code analyzer (C/C++, Obj-C)

# Other

## Build tools

* [checkmake](https://github.com/mrtazz/checkmake) - Linter / Analyzer for Makefiles
* [codechecker](https://github.com/Ericsson/codechecker) - a defect database and viewer extension for the Clang Static Analyzer

## Binaries

* [BinSkim](https://github.com/Microsoft/binskim) - A binary static analysis tool that provides security and correctness results for Windows portable executables.
* [Manalyze](https://github.com/JusticeRage/Manalyze) - A static analyzer, which checks portable executables for malicious content.

## Containers

* [clair](https://github.com/coreos/clair) - Vulnerability Static Analysis for Containers
* [collector](https://github.com/banyanops/collector) - Run arbitrary scripts inside containers, and gather useful information
* [dagda](https://github.com/eliasgranderubio/dagda) - Perform static analysis of known vulnerabilities in docker images/containers.
* [Docker Label Inspector](https://github.com/garethr/docker-label-inspector) - Lint and validate Dockerfile labels
* [Haskell Dockerfile Linter](https://github.com/lukasmartinelli/hadolint) - A smarter Dockerfile linter that helps you build best practice Docker images

## Config Files

* [gixy](https://github.com/yandex/gixy) - a tool to analyze Nginx configuration. The main goal is to prevent misconfiguration and automate flaw detection.

## Configuration Management

* [ansible-lint](https://github.com/willthames/ansible-lint) - Checks playbooks for practices and behaviour that could potentially be improved
* [foodcritic](http://www.foodcritic.io/) - A lint tool that checks Chef cookbooks for common problems. 
* [Puppet Lint](https://github.com/rodjek/puppet-lint) - Check that your Puppet manifests conform to the style guide.

## CSS

* [CSS Stats](https://github.com/cssstats/cssstats) - Potentially interesting stats on stylesheets
* [CSScomb](https://github.com/csscomb/csscomb.js) - a coding style formatter for CSS. Supports own configurations to make style sheets beautiful and consistent
* [CSSLint](https://github.com/CSSLint/csslint) - Does basic syntax checking and finds problematic patterns or signs of inefficiency
* [Parker](https://github.com/katiefenn/parker) - Stylesheet analysis tool
* [sass-lint](https://github.com/sasstools/sass-lint) - A Node-only Sass linter for both sass and scss syntax.
* [scsslint](https://github.com/brigade/scss-lint) - Linter for SCSS files
* [Specificity Graph](https://github.com/pocketjoso/specificity-graph) - CSS Specificity Graph Generator
* [Stylelint](http://stylelint.io/) - Linter for SCSS/CSS files

## HTML

* [HTML Inspector](https://github.com/philipwalton/html-inspector) - HTML Inspector is a code quality tool to help you and your team write better markup.
* [HTML Tidy](http://www.html-tidy.org/) - Corrects and cleans up HTML and XML documents by fixing markup errors and upgrading legacy code to modern standards.
* [HTMLHint](https://github.com/yaniswang/HTMLHint) - A Static Code Analysis Tool for HTML

## IDE Plugins

* [ale](https://github.com/w0rp/ale) - Asynchronous Lint Engine for Vim and NeoVim with support for many languages
* [Attackflow Extension](https://www.attackflow.com/Extension) :copyright: - Attackflow plugin for Visual Studio, which enables developers to find critical security bugs at real time in the source code without any prior knowledge. 
* [Puma Scan](https://github.com/pumasecurity/puma-scan) - Puma Scan provides real time secure code analysis for common vulnerabilities (XSS, SQLi, CSRF, LDAPi, crypto, deserialization, etc.) as development teams write code in Visual Studio.
* [vint](https://github.com/Kuniwak/vint) - Fast and Highly Extensible Vim script Language Lint implemented by Python.

## LaTeX

* [ChkTeX](http://www.nongnu.org/chktex/) - A linter for LaTex which catches some typographic errors LaTeX oversees.
* [lacheck](https://www.ctan.org/pkg/lacheck) - A tool for finding common mistakes in LaTeX documents.

## Makefiles

* [portlint](https://www.freebsd.org/cgi/man.cgi?query=portlint&sektion=1&manpath=FreeBSD+8.1-RELEASE+and+Ports) - A verifier for FreeBSD and DragonFlyBSD port directories

## Markdown

* [mdl](https://github.com/mivok/markdownlint) - A tool to check markdown files and flag style issues.

## Mobile

* [android-lint-summary](https://github.com/passy/android-lint-summary) - Combines lint errors of multiple projects into one output, check lint results of multiple sub-projects at once.
* [FlowDroid](https://github.com/secure-software-engineering/soot-infoflow-android) - static taint analysis tool for Android applications
* [paprika](https://github.com/GeoffreyHecht/paprika) - A toolkit to detect some code smells in analyzed Android applications.
* [qark](https://github.com/linkedin/qark) - Tool to look for several security related Android application vulnerabilities

## Packages

* [lintian](https://github.com/Debian/lintian) - Static analysis tool for Debian packages
* [rpmlint](https://github.com/rpm-software-management/rpmlint) - Tool for checking common errors in rpm packages

## Template-Languages

* [ember-template-lint](https://github.com/rwjblue/ember-template-lint) - Linter for Ember or Handlebars templates.
* [haml-lint](https://github.com/brigade/haml-lint) - Tool for writing clean and consistent HAML
* [slim-lint](https://github.com/sds/slim-lint) - Configurable tool for analyzing Slim templates
* [yamllint](https://github.com/adrienverge/yamllint) - Checks YAML files for syntax validity, key repetition and cosmetic problems such as lines length, trailing spaces, and indentation.

## Translation

* [dennis](https://github.com/willkg/dennis/) - A set of utilities for working with PO files to ease development and improve quality.

## Writing

* [misspell fixer](https://github.com/vlajos/misspell_fixer) - Quick tool for fixing common misspellings, typos in source code
* [proselint](https://github.com/amperser/proselint/) - a linter for English prose with a focus on writing style instead of grammar.
* [vale](https://github.com/ValeLint/vale) - A customizable, syntax-aware linter for prose.

## Web services

* [Attackflow](https://www.attackflow.com) :copyright: - Application security testing tool with rules grouped into nine classes including Authorization, Injection, Cryptography, Authentication and Code Quality.
* [Bithound](https://www.bithound.io/) :copyright: - Code Analysis beyond Lint, specifically for Node.js.
* [Codacy](https://www.codacy.com/) :copyright: - Code Analysis to ship Better Code, Faster.
* [Code Climate](https://codeclimate.com/) :copyright: - The open and extensible static analysis platform, for everyone.
* [CodeFactor](https://codefactor.io) :copyright: - Automated Code Analysis for repos on GitHub or BitBucket. 
* [Functor Prevent](http://www.functor.se/products/prevent/) :copyright: - Static code analysis for C code.
* [kiuwan](https://www.kiuwan.com/) :copyright: - Software Analytics in the Cloud supporting more than 22 programming languages.
* [Landscape](https://landscape.io/) :copyright: - Static code analysis for Python
* [Nitpick CI](https://nitpick-ci.com) :copyright: - Automated PHP code review
* [Node Security Platform](https://nodesecurity.io/) :copyright: - Continuous Security monitoring for your node apps (free for Open Source Projects)
* [QuantifiedCode](https://www.quantifiedcode.com/) :copyright: - Automated code review & repair
* [Scrutinizer](https://scrutinizer-ci.com/) :copyright: - A proprietery code quality checker that can be integrated with GitHub
* [SensioLabs Insight](https://insight.sensiolabs.com/) :copyright: - Detect security risks, find bugs and provide actionable metrics for PHP projects
* [SideCI](https://sideci.com) :copyright: - An automated code reviewing tool. Improving developers' productivity.
* [Snyk](https://snyk.io/) :copyright: - Vulnerability scanner for dependencies of node.js apps (free for Open Source Projects)
* [Teamscale](http://www.teamscale.com/) :copyright: - Static and dynamic analysis tool supporting more than 25 languages and direct IDE integration. Free hosting for Open Source projects available on request. Free academic licenses available.
* [Upsource](https://www.jetbrains.com/upsource/) :copyright: - Code review tool with static code analysis and code-aware navigation for Java, PHP, JavaScript and Kotlin.

# More collections

* [go-tools](https://github.com/dominikh/go-tools) - A collection of tools and libraries for working with Go code, including linters and static analysis
* [linters](https://github.com/mcandre/linters) - An introduction to static code analysis
* [php-static-analysis-tools](https://github.com/exakat/php-static-analysis-tools) -  A reviewed list of useful PHP static analysis tools
* [Tools for C/C++](https://www.peerlyst.com/posts/a-list-of-static-analysis-tools-for-c-c-peerlyst?utm_source=twitter&utm_medium=social&utm_content=peerlyst_post&utm_campaign=peerlyst_resources) - A list of static analysis tools for C/C++
* [Wikipedia](http://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis) -  A list of tools for static code analysis.

## License

[![CC0](https://i.creativecommons.org/p/zero/1.0/88x31.png)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, [Matthias Endler](http://matthias-endler.de) has waived all copyright and related or neighboring rights to this work. 
Title image [Designed by Freepik](http://www.freepik.com).



# The Java Code Review Checklist

A code review guide and checklist when working with Java and related technologies. The following should really help when writing new code in Java applications after upgrading to Java 8 or refactoring code that is < Java8

# Core Java 

## Prefer Lambdas

Instead of 

```
Runnable runner = new Runnable(){
    public void run(){
        System.out.println("I am running");
    }
};
```

do...

```
Runnable running = () -> {
    System.out.println("I am running");
};
```

## Refactor interfaces with default methods

Instead of 

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
  public void saySomething(); 
 
}
```

Use default methods. Make sure you do not do this as a a habit because this pattern pollutes interfaces.

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
 
    public void saySomething();
 
    default public void sayHi() {
      System.out.println("Hi");
    }
 
}
```

## Prefer Streams to reduce code.

```
private static void printNames(List persons, Predicate predicate) {
            persons.stream()
                    .filter(predicate)
                    .map(p -> p.getName())
                    .forEach(name -> System.out.println(name));
        }
}
```

## Use Parallel sorting

Instead of 

```
Array.sort(myArray);
```

Use...

```
Arrays.parallelSort(myArray);
```

## Depend on parameter reflection

Instead of...

```
Person getEmployee(@PathParam("dept") Long dept, @QueryParam("id") Long id)
```

Do...

```
Person getEmployee(@PathParam Long dept, @QueryParam Long id)
```

Since params names as same as var names.

## Prefer to use "filter / map / reduce" approach

```
List<String> names = Arrays.asList("Smith", "Adams", "Crawford"); 
List<Person> people = peopleDAO.find("London"); 
  
// Using anyMatch and method reference 
List<Person> anyMatch = people.stream().filter(p -> (names.stream().anyMatch(p.name::contains))).collect(Collectors.toList()); 
  
// Using reduce 
List<Person> reduced = people.stream().filter(p -> names.stream().reduce(false (Boolean b, String keyword) -> b || p.name.contains(keyword), (l, r) -> l | r)).collect(Collectors.toList()); 
```

# Use new data-time api

```
Clock clock = Clock.systemUTC(); //return the current time based on your system clock and set to UTC. 

Clock clock = Clock.systemDefaultZone(); //return time based on system clock zone 

long time = clock.millis(); //time in milliseconds from January 1st, 1970
```


# The Java Code Review Checklist

A code review guide and checklist when working with Java and related technologies. The following should really help when writing new code in Java applications after upgrading to Java 8 or refactoring code that is < Java8

# Core Java 

## Prefer Lambdas

Instead of 

```
Runnable runner = new Runnable(){
    public void run(){
        System.out.println("I am running");
    }
};
```

do...

```
Runnable running = () -> {
    System.out.println("I am running");
};
```

## Refactor interfaces with default methods

Instead of 

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
  public void saySomething(); 
 
}
```

Use default methods. Make sure you do not do this as a a habit because this pattern pollutes interfaces.

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
 
    public void saySomething();
 
    default public void sayHi() {
      System.out.println("Hi");
    }
 
}
```

## Prefer Streams to reduce code.

```
private static void printNames(List persons, Predicate predicate) {
            persons.stream()
                    .filter(predicate)
                    .map(p -> p.getName())
                    .forEach(name -> System.out.println(name));
        }
}
```

## Use Parallel sorting

Instead of 

```
Array.sort(myArray);
```

Use...

```
Arrays.parallelSort(myArray);
```

## Depend on parameter reflection

Instead of...

```
Person getEmployee(@PathParam("dept") Long dept, @QueryParam("id") Long id)
```

Do...

```
Person getEmployee(@PathParam Long dept, @QueryParam Long id)
```

Since params names as same as var names.

## Prefer to use "filter / map / reduce" approach

```
List<String> names = Arrays.asList("Smith", "Adams", "Crawford"); 
List<Person> people = peopleDAO.find("London"); 
  
// Using anyMatch and method reference 
List<Person> anyMatch = people.stream().filter(p -> (names.stream().anyMatch(p.name::contains))).collect(Collectors.toList()); 
  
// Using reduce 
List<Person> reduced = people.stream().filter(p -> names.stream().reduce(false (Boolean b, String keyword) -> b || p.name.contains(keyword), (l, r) -> l | r)).collect(Collectors.toList()); 
```

# Use new data-time api

```
Clock clock = Clock.systemUTC(); //return the current time based on your system clock and set to UTC. 

Clock clock = Clock.systemDefaultZone(); //return time based on system clock zone 

long time = clock.millis(); //time in milliseconds from January 1st, 1970
```


##
##

Code reviews, or peer reviews, can sometimes feel like an unnecessary chore, especially when there is a backlog of features to work on, leaving very little time for these reviews. However, manual or automated reviews are essential to delivering quality code that provides a great customer experience.

This guide covers some of the most common items to check in a Java code review to ensure your code is reliable and easy to read, maintain and scale.

1. Ensure the code follows standard naming conventions
Meaningful naming conventions help ensure the readability and maintainability of the application.

As such, ensure variable, method, and class names convey the subject:

addPerson()
Could be clarified to:

addEmployee()
Use all lower cases for package names and use reversed Internet domain naming conventions:

org/companyname/appname
Class names should start with Capitals:

Employee, Student,
Variable and method names should use CamelCase:

employeeList, studentName, displayEmployees()
2. Make sure it handles constants efficiently
Constants help improve memory as they are cached by the JVM. For values that are reused across multiple places, create a constant file that holds static values.

Favor database-driven values over dynamic values. Also, use ENUMs to group constants.

3. Check for proper clean Up
It is common during development to use procedures that help with your coding and debugging (hard coded variables, for example). It is good practice to remove these items and others such as:

Console print statements
Unnecessary comments
Use @deprecated on method/variable names that aren’t meant for future use
4. Handle strings appropriately
If you need to perform a lot of operations on a String, use StringBuilder or StringBuffer.

Strings are immutable, whereas StringBuilder and StringBuffer are mutable and can be changed. Additionally, a new String object is created for every concatenation operation.

Rather than creating multiple items, using a mutable object is preferred.

5. Optimize to use switch-case over multiple If-Else statements
Rather than using multiple if-else conditions, use the cleaner and more readable switch-case.

Doing so makes the logic cleaner and optimizes the app's performance.

switch(expression) {

 case x:

// code block

   break;

case y:

  // code block

   break;

 default:

   // code block

}

6. Ensure the code follows appropriate error handling procedures
The NullPointerException is one of the most common and frustrating exceptions.

However, they can be avoided by performing a null check on a variable before operating on it.

The best practice is to use checked exceptions for recoverable operations and use runtime exceptions for programming errors.

Another area to evaluate during a Java code review is to ensure all exceptions are wrapped in custom exceptions.

In this way, the stack trace is preserved, making it easier to debug when things go wrong.

Also, it should declare specific checked exceptions that the method throws rather than generic ones. Doing so doesn’t give you the option to handle and debug the issue appropriately.

Avoid this:

public void hello() throws Exception { //Incorrect way

}

Try this instead:

public void hello() throws SpecificException1, SpecificException2 { //Correct way

}

Use the try-catch block for exception handling with appropriate actions taken in the catch block.

Also, use a finally block to release resources, such as database connections, in the finally block. This allows you to close the resource gracefully.

7. Avoid unnecessary comments in code?
Comments should not be used to explain code. If the logic is not intuitive, it should be rewritten. Use comments to answer a question that the code can’t.

Another way to state it is that the comment should explain the “why” versus “what” it does.

8. Validate that the code follows separation of concerns
Ensure there is no duplication. Each class or method should be small and focus on one thing.

For example:

EmployeeDao.java - Data access logic

Employee.java - Domain Logic

EmployeerService.java - Business Logic

EmployeeValidator.java - Validating Input Fields

9. Does the code rely on frameworks rather than custom logic when possible?
When time is of the essence, reinventing the wheel is time wasted. There are plenty of proven frameworks and libraries available for the most common use cases you may need.

Examples include Apache Commons libraries, Spring libraries, and XML/JSON libraries.

10. Make sure variables don’t cause memory leaks
Creating a bunch of unnecessary variables can overwhelm the heap and lead to memory leaks and cause performance problems. This occurs when an object is present in the heap but is no longer used, and the garbage collection cannot remove it from memory.

Example:

Avoid This

boolean removed = myItems.remove(item); return removed;
Try This Instead

return myItems.remove(item);
Performing regular Java code reviews can help identify issues before the application makes it to production.

The more thorough you are about the process, the less chance you’ll miss anything that could be added to your backlog.




# The Java Code Review Checklist

A code review guide and checklist when working with Java and related technologies. The following should really help when writing new code in Java applications after upgrading to Java 8 or refactoring code that is < Java8

# Core Java 

## Prefer Lambdas

Instead of 

```
Runnable runner = new Runnable(){
    public void run(){
        System.out.println("I am running");
    }
};
```

do...

```
Runnable running = () -> {
    System.out.println("I am running");
};
```

## Refactor interfaces with default methods

Instead of 

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
  public void saySomething(); 
 
}
```

Use default methods. Make sure you do not do this as a a habit because this pattern pollutes interfaces.

```
public class MyClass implements InterfaceA {
 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
 
    @Override
    public void saySomething() {
        System.out.println("Hello World");
    }
 
}
 
interface InterfaceA {
 
    public void saySomething();
 
    default public void sayHi() {
      System.out.println("Hi");
    }
 
}
```

## Prefer Streams to reduce code.

```
private static void printNames(List persons, Predicate predicate) {
            persons.stream()
                    .filter(predicate)
                    .map(p -> p.getName())
                    .forEach(name -> System.out.println(name));
        }
}
```

## Use Parallel sorting

Instead of 

```
Array.sort(myArray);
```

Use...

```
Arrays.parallelSort(myArray);
```

## Depend on parameter reflection

Instead of...

```
Person getEmployee(@PathParam("dept") Long dept, @QueryParam("id") Long id)
```

Do...

```
Person getEmployee(@PathParam Long dept, @QueryParam Long id)
```

Since params names as same as var names.

## Prefer to use "filter / map / reduce" approach

```
List<String> names = Arrays.asList("Smith", "Adams", "Crawford"); 
List<Person> people = peopleDAO.find("London"); 
  
// Using anyMatch and method reference 
List<Person> anyMatch = people.stream().filter(p -> (names.stream().anyMatch(p.name::contains))).collect(Collectors.toList()); 
  
// Using reduce 
List<Person> reduced = people.stream().filter(p -> names.stream().reduce(false (Boolean b, String keyword) -> b || p.name.contains(keyword), (l, r) -> l | r)).collect(Collectors.toList()); 
```

# Use new data-time api

```
Clock clock = Clock.systemUTC(); //return the current time based on your system clock and set to UTC. 

Clock clock = Clock.systemDefaultZone(); //return time based on system clock zone 

long time = clock.millis(); //time in milliseconds from January 1st, 1970
```


```
package java.snippet.account;

import java.util.*;

public class Account {
	public long id;
	public double balance;
	public Map transactions;

	public Account() {
		this.id = System.currentTimeMillis();
		this.balance = 0;
		this.transactions = new TreeMap();
	}

	public void deposit(double amount) {
		balance += amount;
		transactions.put(new Date(), amount);
	}

	public void withdraw(double amount) {
		balance -= amount;
		transactions.put(new Date(), -amount);
	}

	public void chargeFee(double amount) {
		balance -= amount;
		transactions.put(new Date(), -amount);
	}
	
	public String transactionsAsString(){
		String strTransactions = "";
		for(Iterator itr = transactions.keySet().iterator(); itr.hasNext();){
			Object when = itr.next();
			strTransactions += " - " + when + " : " + transactions.get(when) + "\n";
		}	
		return strTransactions;		
	}

	public static void main(String[] args) {
		Account account = new Account();
		account.deposit(100);
		account.withdraw(70);
		account.chargeFee(5.50);

		System.out.println("id : " + account.id);			// is non-zero?
		System.out.println("balance : " + account.balance);	// equals 24.50?
		System.out.println("transactions : ");
		System.out.println(account.transactionsAsString());	// shows 3 transactions
	}
}
```

##
##

To use grep to search for sensitive strings, passwords, and usernames in Java files within a directory and its subdirectories, you can combine it with find to traverse the directory tree. The -r (or --recursive) option is used to search recursively. Please keep in mind that searching for sensitive information like passwords or usernames in code files should only be done on your own codebase or with explicit permission from the code owner.

Here's the command you can use:

bash
Copy code
find /path/to/your/directory -type f -name "*.java" -exec grep -Ei "(password|username|sensitive_string)" {} +
Explanation:

find /path/to/your/directory: This starts the search from the specified directory and its subdirectories.
-type f: This option makes find search only for regular files (not directories or other file types).
-name "*.java": This specifies that find should only look for files with the ".java" extension.
-exec grep -Ei "(password|username|sensitive_string)" {} +: This tells find to execute grep on the found files. The -E option enables extended regular expressions (to use the | for multiple patterns), and the -i option makes the search case-insensitive. The {} is a placeholder for the file name, and + at the end ensures that multiple file names are passed to a single grep command to improve efficiency.
Please replace /path/to/your/directory with the actual path to the directory you want to search in. The command will display any lines in the Java files that match the specified patterns. Double-check the results before taking any actions, as some legitimate code constructs might also contain these keywords. Always be careful when handling potentially sensitive information.






##
##
##


grep all .java files in a directory for a particular string
Asked 14 years ago
Modified 3 years, 1 month ago
Viewed 20k times
13

How would I search all .java files for a simple string (not a regex) in the current directory and all sub-directories on Mac OS X? I just want to print a list of file and directory names that match.

macosmacunixgrep
Share
Improve this question
Follow
edited Aug 6, 2009 at 16:51
John T's user avatar
John T
163k2727 gold badges340340 silver badges347347 bronze badges
asked Jul 15, 2009 at 20:06
John Topley's user avatar
John Topley
1,72833 gold badges1818 silver badges2222 bronze badges
Thanks for asking this so I don't have to. Now I just have to figure out how to exclude ".git" and I'm done for a bit. – 
Dan Rosenstark
 Nov 16, 2010 at 21:13
I think js's answer is more concise, still sucks you have to type out --include, but still. Could probably just write an alias to hide that – 
Craig Tataryn
 Jul 5, 2011 at 16:14
Add a comment
9 Answers
Sorted by:

Highest score (default)
19

And the always popular

find . -name '*.java' | xargs grep -l 'string'
EDIT (by Frank Szczerba):

If you are dealing with filenames or directories that have spaces in them, the safest way to do this is:

find . -name '*.java' -print0 | xargs -0 grep -l 'string'
There's always more than one way to do it.

Share
Improve this answer
Follow
edited Aug 13, 2011 at 5:56
Tamara Wijsman's user avatar
Tamara Wijsman
57.1k2727 gold badges185185 silver badges256256 bronze badges
answered Jul 15, 2009 at 20:13
David Mackintosh's user avatar
David Mackintosh
3,93477 gold badges3333 silver badges4242 bronze badges
mdfind is a more OSXy way to do this! – 
user22908
 Oct 10, 2011 at 20:43
Add a comment
11

The traditional UNIX answer would be the one that was accepted for this question:

find . -name '*.java' | xargs grep -l 'string'
This will probably work for Java files, but spaces in filenames are a lot more common on Mac than in the traditional UNIX world. When filenames with spaces are passed through the pipeline above, xargs will interpret the individual words as different names.

What you really want is to nul-separate the names to make the boundaries unambiguous:

find . -name '*.java' -print0 | xargs -0 grep -l 'string'
The alternative is to let find run grep for you, as Mark suggests, though that approach is slower if you are searching large numbers of files (as grep is invoked once per file rather than once with the whole list of files).

Share
Improve this answer
Follow
answered Jul 31, 2009 at 15:24
Frank Szczerba's user avatar
Frank Szczerba
51544 silver badges1111 bronze badges
You can also use the "--replace" option in xargs to deal with filenames having spaces in them: ... | xargs --replace grep 'string' '{}' ({} would be replaced by the filename) – 
arathorn
 Aug 6, 2009 at 15:41
1
Modern versions of find (including the one installed on OS X) support "-exec <command> {} +" where the plus sign at the end (instead of \;) tells find to replace {} with "as many pathnames as possible... This is is similar to that of xargs(1)" (from the man page). – 
Doug Harris
 Aug 6, 2009 at 16:23
Add a comment
8

Use the grep that is better than grep, ack:

ack -l --java  "string" 
Share
Improve this answer
Follow
edited Jul 16, 2009 at 6:49
answered Jul 15, 2009 at 20:23
bortzmeyer's user avatar
bortzmeyer
1,1711111 silver badges1111 bronze badges
3
ack isn't installed on Mac OS X by default. – 
John Topley
 Jul 15, 2009 at 20:25
I don't know what "by default" means. On many OS, you choose what you install so it is difficult to find programs which are always present. At a time, a C compiler was always there and Perl was uncommon... – 
bortzmeyer
 Jul 15, 2009 at 20:34
1
It means that it's part of the standard OS install. I have the developer tools installed on my Mac and they don't install ack. You have to install it yourself. If you have it, then it's a nice syntax. – 
John Topley
 Jul 15, 2009 at 20:41
In the case of ack, it's a single Perl program with no module dependencies. If you can "install" programs in your ~/bin directory, then you can just as easily "install" ack. – 
Andy Lester
 May 3, 2010 at 18:53
Add a comment
6

grep -rl --include="*.java" simplestring *
Share
Improve this answer
Follow
edited Jul 6, 2011 at 14:39
answered Aug 6, 2009 at 22:31
js.'s user avatar
js.
17311 silver badge44 bronze badges
2
This seems to be the best answer here - if grep does it all, why use find & xargs? – 
Peter Gibson
 Jul 13, 2010 at 2:05
FYI, given what's asked in the question, it should be small "l" not big "L" in that command – 
Craig Tataryn
 Jul 5, 2011 at 16:18
Craig is right, I corrected my answer. – 
js.
 Jul 6, 2011 at 14:40
Add a comment
4

This will actually use a regex if you want, just stay away from the metacharacters, or escape them, and you can search for strings.

find . -iname "*.java" -exec egrep -il "search string" {} \;
Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:10
Mark Thalman's user avatar
Mark Thalman
9781010 silver badges1515 bronze badges
Add a comment
1

Since this is an OSX question, here is a more OSX specific answer.
Skip find and use Spotlight from the command line. Much more powerful!

COMMAND LINE SPOTLIGHT – FIND MEETS GREP

Most people don’t know you can do Spotlight searches from the command line. Why remember all the arcane find and grep options and what not when you can let Spotlight do the work for you. The command line interface to Spotlight is called mdfind. It has all the same power as the GUI Spotlight search and more because it is scriptable at the command line!

Share
Improve this answer
Follow
edited Jun 12, 2020 at 13:48
Community's user avatar
CommunityBot
1
answered Oct 10, 2011 at 20:41
user22908
Add a comment
0

Give this a go:

grep -rl "string" */*java
Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:09
dwj's user avatar
dwj
1,44455 gold badges2121 silver badges2626 bronze badges
1
This gives "grep: */*java: No such file or directory" on Mac OS X. – 
John Topley
 Jul 15, 2009 at 20:12
The problem here is that it will only find *.java files one level deep. See Mark Thalman's answer for IMHO the proper way to do it. – 
Ludwig Weinzierl
 Jul 15, 2009 at 20:17
Sorry, not at my Mac. Doesn't the Mac version of grep have the -r (recursive) flag? – 
dwj
 Jul 15, 2009 at 20:36
It does, but that was the output that I got when searching for a string that I know is in the files. – 
John Topley
 Jul 15, 2009 at 20:40
Add a comment
0

You could also use a GUI program like TextWrangler to do a more intuitive search where the options are in the interface.

Share
Improve this answer
Follow
answered Jul 15, 2009 at 20:13
Mark Thalman's user avatar
Mark Thalman
9781010 silver badges1515 bronze badges
Add a comment
0

grep "(your string)" -rl $(find ./ -name "*.java")
If you want to ignore case, replace -rl with -irl. (your string) may also be a regex if you ever see the need.

Share
Improve this answer
Follow
