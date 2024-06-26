# Deobfuscating / Unminifying Obfuscated Web App / JavaScript Code

##
#
https://gist.github.com/0xdevalias/d8b743efb82c0e9406fc69da0d6c6581
#
##

## Table of Contents

<!-- TOC start (generated with https://derlin.github.io/bitdowntoc/) -->

- [PoC](#poc)
- [Tools](#tools)
   - [Unsorted](#unsorted)
   - [wakaru](#wakaru)
   - [webcrack](#webcrack)
   - [ast-grep](#ast-grep)
   - [Restringer](#restringer)
   - [debundle + related](#debundle--related)
   - [joern](#joern)
- [Blogs / Articles / etc](#blogs--articles--etc)
- [Libraries / Helpers](#libraries--helpers)
   - [Unsorted](#unsorted-1)
   - [Recast + related](#recast--related)
   - [estools + related](#estools--related)
   - [Babel](#babel)
   - [`semantic` / `tree-sitter` + related](#semantic--tree-sitter--related)
   - [Shift AST](#shift-ast)
   - [`swc`](#swc)
   - [`esbuild`](#esbuild)
   - [Source Maps](#source-maps)
   - [Visualisation/etc](#visualisationetc)
- [Browser Based Code Editors / IDEs](#browser-based-code-editors--ides)
   - [CodeMirror](#codemirror)
   - [`monaco-editor`](#monaco-editor)
- [Obfuscation / Deobfuscation](#obfuscation--deobfuscation)
   - [Variable Name Mangling](#variable-name-mangling)
- [Stack Graphs / Scope Graphs](#stack-graphs--scope-graphs)
- [Symbolic / Concolic Execution](#symbolic--concolic-execution)
- [Profiling](#profiling)
- [Unsorted](#unsorted-2)
- [My ChatGPT Research / Conversations](#my-chatgpt-research--conversations)
- [See Also](#see-also)
   - [My Other Related Deepdive Gist's and Projects](#my-other-related-deepdive-gists-and-projects)

<!-- TOC end -->

**Other files in this gist:**

- [`chrome-devtools-sources-extension.md`](#chrome-devtools-sources-extension)
  - > Chrome DevTools 'Sources' Extension
- [`fingerprinting-minified-javascript-libraries.md`](#file-fingerprinting-minified-javascript-libraries-md)
  - > Fingerprinting Minified JavaScript Libraries

## PoC

- https://replit.com/@0xdevalias/Rewriting-JavaScript-Variables-via-AST-Examples
  - https://github.com/0xdevalias/poc-ast-tools
    - > poc-ast-tools
      > PoC scripts and tools for working with (primarily JavaScript) ASTs.

## Tools

### Unsorted

- https://eslint.org/docs/
  - https://eslint.org/docs/latest/extend/custom-rules#the-context-object
    - > The context object is the only argument of the create method in a rule.
    - > As the name implies, the context object contains information that is relevant to the context of the rule.
  - https://eslint.org/docs/latest/extend/custom-rules#applying-fixes
    - > Applying Fixes
      > If you’d like ESLint to attempt to fix the problem you’re reporting, you can do so by specifying the fix function when using `context.report()`. The `fix` function receives a single argument, a `fixer` object, that you can use to apply a fix.
    - > Important: The `meta.fixable` property is mandatory for fixable rules. ESLint will throw an error if a rule that implements `fix` functions does not export the `meta.fixable` property.
    - > The `fixer` object has the following methods:
      > 
      > -   `insertTextAfter(nodeOrToken, text)`: Insert text after the given node or token.
      > -   `insertTextAfterRange(range, text)`: Insert text after the given range.
      > -   `insertTextBefore(nodeOrToken, text)`: Insert text before the given node or token.
      > -   `insertTextBeforeRange(range, text)`: Insert text before the given range.
      > -   `remove(nodeOrToken)`: Remove the given node or token.
      > -   `removeRange(range)`: Remove text in the given range.
      > -   `replaceText(nodeOrToken, text)`: Replace the text in the given node or token.
      > -   `replaceTextRange(range, text)`: Replace the text in the given range.
      > 
      > A `range` is a two-item array containing character indices inside the source code. The first item is the start of the range (inclusive) and the second item is the end of the range (exclusive). Every node and token has a `range` property to identify the source code range they represent.
      > 
      > The above methods return a `fixing` object. The `fix()` function can return the following values:
      > 
      > -   A `fixing` object.
      > -   An array which includes `fixing` objects.
      > -   An iterable object which enumerates `fixing` objects. Especially, the `fix()` function can be a generator.
      > 
      > If you make a `fix()` function which returns multiple `fixing` objects, those `fixing` objects must not overlap.
  - https://eslint.org/docs/latest/extend/code-path-analysis
    - > Code Path Analysis Details
    - > ESLint’s rules can use code paths. The code path is execution routes of programs. It forks/joins at such as `if` statements.
    - > Program is expressed with several code paths. A code path is expressed with objects of two kinds: `CodePath` and `CodePathSegment`.
    - > `CodePath` expresses whole of one code path. This object exists for each function and the global. This has references of both the initial segment and the final segments of a code path.
    - > `CodePathSegment` is a part of a code path. A code path is expressed with plural `CodePathSegment` objects, it’s similar to doubly linked list. Difference from doubly linked list is what there are forking and merging (the next/prev are plural).
    - > There are seven events related to code paths, and you can define event handlers by adding them alongside node visitors in the object exported from the `create()` method of your rule.
- https://prettier.io/
  - https://github.com/prettier/prettier
    - > Prettier is an opinionated code formatter. It enforces a consistent style by parsing your code and re-printing it with its own rules that take the maximum line length into account, wrapping code when necessary.
    - https://prettier.io/docs/en/options#parser
      - > Parser
        > Specify which parser to use.
        > Prettier automatically infers the parser from the input file path, so you shouldn’t have to change this setting.
    - https://prettier.io/docs/en/api.html
      - > API
        > If you want to run Prettier programmatically, check this page out.
- https://github.com/beautify-web/js-beautify
  - > Beautifier for javascript
  - > This little beautifier will reformat and re-indent bookmarklets, ugly JavaScript, unpack scripts packed by Dean Edward’s popular packer, as well as partly deobfuscate scripts processed by the npm package `javascript-obfuscator`.
  - https://beautifier.io/
- https://github.com/shapesecurity/unminify
  - > Reverse many of the transformations applied by minifiers and naïve obfuscators
  - https://github.com/shapesecurity/unminify/#safety-levels
  - https://unminify.io/
- https://github.com/lelinhtinh/de4js
  - > JavaScript Deobfuscator and Unpacker
  - https://lelinhtinh.github.io/de4js/
  - https://github.com/lelinhtinh/de4js/blob/master/userscript/de4js_helper.user.js
- http://www.jsnice.org/
  - > Statistical renaming, type inference and deobfuscation
  - https://www.sri.inf.ethz.ch/research/plml
    - > Machine Learning for Code
      > This project combines programming languages and machine learning for building statistical programming engines -- systems built on top of machine learning models of large codebases. These are new kinds of engines which can provide statistically likely solutions to problems that are difficult or impossible to solve with traditional techniques.
    - > JSNice
      > JSNice de-obfuscates JavaScript programs. JSNice is a popular system in the JavaScript commmunity used by tens of thousands of programmers, worldwide
- https://github.com/spaceraccoon/webpack-exploder/
  - > Unpack the source code of React and other Webpacked apps!
  - https://github.com/spaceraccoon/webpack-exploder/blob/master/index.html#L225-L286
    - This basically just extracts the original files from a sourcemap `*.map` file
  - https://spaceraccoon.github.io/webpack-exploder/
- https://github.com/goto-bus-stop/webpack-unpack
  - > extract modules from a bundle generated by webpack
  - https://github.com/goto-bus-stop/webpack-unpack/blob/master/index.js
- https://github.com/goto-bus-stop/amd-unpack
  - > extract modules from a bundled AMD project using define/require functions
- https://github.com/gchq/CyberChef
  - > The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis
  - https://gchq.github.io/CyberChef/
    - Javascrpt Parser: https://gchq.github.io/CyberChef/#recipe=JavaScript_Parser(false,false,false,false,false)
- https://github.com/dandavison/delta
  - > A syntax-highlighting pager for git, diff, and grep output
  - > (the package is called "git-delta" in most package managers, but the executable is just delta)
  - https://dandavison.github.io/delta/introduction.html
- https://github.com/Wilfred/difftastic
  - > Difftastic is a structural diff tool that compares files based on their syntax.
  - https://difftastic.wilfred.me.uk/introduction.html
    - > Difftastic is a structural diff tool that understands syntax. It supports over 30 programming languages and when it works, it's fantastic.
- https://github.com/prettydiff/prettydiff
  - > Beautifier and language aware code comparison tool for many languages. It also minifies and a few other things
  - https://prettydiff.com/#projects-prettydiff
    - > When I first became a developer at Travelocity I would sometimes needs to compare code in different environments where some code existed in its original condition and in other cases was minified. Existing diff tools could not solve for that sort of comparison, and at that time existing JavaScript beautifiers had trouble with complex data structures. So I integrated a web-based diff tool with an existing beautifier and minifier. As the features, capabilities, and requests upon the application grew I eventually wrote my own diff algorithm and beautifiers for the various supported languages.
- https://github.com/Vunovati/astii
  - > A JavaScript AST-aware diff and patch toolset
  - > When comparing two JavaScript files, standard diff tools compare the two files line-by-line and output the lines on which the files differ. This tool does not compare the characters of the source files directly but their abstract representation - their abstract syntax trees.
  - > This enables you to have more meaningfull diffs between files which may be very simmilar but have different source code formatting.
  - > When patching, astii patch will regenerate (`original --> AST --> generate`) the source file and patch it with the provided diff.
- https://www.blueclosure.com/product/bc-detect
  - > BC Detect (DOMinatorPro NG) helps security testers to analyse and automatically discover DOM Based Cross Site Scripting issues thanks to its Hybrid IAST Engine together with the Smart Fuzzer module.
  - https://www.blueclosure.com/page/features
- https://github.com/kuizuo/js-deobfuscator
  - > JS obfuscated code restoration
    > Let confusion no longer be a stumbling block in reverse analysis
    > https://js-deobfuscator.vercel.app/

### wakaru

- https://github.com/pionxzh/wakaru
  - > Javascript decompiler, unpacker and unminify toolkit
  - > Wakaru is the Javascript decompiler for modern frontend. It brings back the original code from a bundled and transpiled source.
  - https://wakaru.vercel.app/
  - https://github.com/pionxzh/wakaru/blob/main/packages/unpacker/src/unpack.ts
    - Uses `jscodeshift.withParser('babylon')`
    - First checks for webpack with `getModulesFromWebpack`, then tries `getModulesFromBrowserify`, and finally falls back to a single module if those both failed
    - https://github.com/pionxzh/wakaru/blob/b06d0a7d8682042700398f0bbba1d76839fb57cf/packages/playground/src/pages/Uploader.vue#L80-L158
      - `async function startUnpack(code: string)`
        - ```js
          // TODO: Move to worker
          const { modules, moduleIdMapping } = unpack(code)
          const unpackedModules = modules.map<TransformedModule>((module) => {
              const { id, isEntry, code, tags } = module
              return {
                  id,
                  isEntry,
                  code,
                  transformed: code,
                  import: module.import,
                  export: module.export,
                  tags,
              }
          })
          ```
  - https://github.com/pionxzh/wakaru/tree/main/packages/unpacker/src/extractors
    - https://github.com/pionxzh/wakaru/blob/main/packages/unpacker/src/extractors/browserify/index.ts
    - https://github.com/pionxzh/wakaru/tree/main/packages/unpacker/src/extractors/webpack
  - https://github.com/pionxzh/wakaru/tree/main/packages/unminify
    - > @wakaru/unminify
      > This package offers a comprehensive set of transformation rules designed to unminify and enhance the readability of code.
      > 
      > It covered most of patterns that are used by the following tools:
      > 
      > - Terser (Check the Terser Progress)
      > - Babel (Check the Babel Progress)
      > - SWC (Check the SWC Progress)
      > - TypeScript
    - https://github.com/pionxzh/wakaru/tree/main/packages/unminify#smart-rename
      - > Rename minified identifiers with heuristic rules.
    - https://github.com/pionxzh/wakaru/blob/main/packages/unminify/src/transformations/smart-rename.ts
      - `handleDestructuringRename`, `handleFunctionParamsRename`, `handlePropertyRename`, `handleReactRename`, `getElementName`
    - https://github.com/pionxzh/wakaru/blob/main/packages/unminify/src/utils/identifier.ts#L28-L75
      - `generateName`, `getUniqueName`
  - https://github.com/pionxzh/wakaru/issues/32
    - > Scoping issue
    - > The current identifier renaming is not 100% accurate. By inspecting the unpacking snapshot, you can tell that some variable was wrongly renamed to export or require during the unpacking process. Mostly because ast-types are giving us wrong scope information, and it's no longer well-maintained. We need to either patch it or find an alternative.
  - https://github.com/pionxzh/wakaru/issues/34
    - > support un-mangle identifiers
    - > Hi, currently we don't have the un-mangle feature yet. You can use other tools for the first pass, and let wakaru handle syntax-related unminification. I will transform this issue to a feature request, so that we can track the progress of it here.
    - > For now, we have `smart-rename` that can guess the variable name based on the context. I would like to expand it to cover some other generic cases.
  - https://github.com/pionxzh/wakaru/issues/36
    - > jsx formats that cannot be handled
  - https://github.com/pionxzh/wakaru/issues/35
    - > Split code and save progress?
  - https://github.com/pionxzh/wakaru/issues/37
    - > Add CLI tool
  - https://github.com/pionxzh/wakaru/issues/45
    - > wakaru IDE

### webcrack

- https://github.com/j4k0xb/webcrack
  - > Deobfuscate obfuscator.io, unminify and unpack bundled javascript
  - https://webcrack.netlify.app/ (Playground)
    - https://webcrack.netlify.app/docs/
    - https://webcrack.netlify.app/docs/guide/introduction.html
  - https://github.com/j4k0xb/webcrack/tree/master/src/transforms
  - https://github.com/j4k0xb/webcrack/tree/master/src/deobfuscator
  - https://github.com/j4k0xb/webcrack/issues/3
    - > Awesome project - looking for help?
    - > I have a project idea I'd like to discuss around unmangling variable names actually, that I think you'll find very interesting as well. Let me know if you'd like to discuss more and we could have a call
      > I'll show you a POC for that next week so you can let me know your thoughts.
  - https://github.com/j4k0xb/webcrack/issues/21
    - > rename short identifiers
  - https://github.com/j4k0xb/webcrack/issues/10
    - > hardcoded React UMD global
    - > The current Sketchy implementation only decompiles React JSX when the code utilizes the UMD global, which is not effective since the majority of React websites incorporate the library within their bundle.
      > 
      > To make the decompilation process more effective and adaptable to different React websites, I recommend a more dynamic approach by identifying the React library being used in the compiled code, instead of hardcoding the use of 'React'. This can possibly be achieved by finding the variable name assigned to the React library and using that in the matchers.
  - https://github.com/j4k0xb/webcrack/issues/6
    - > `(0, fn)(...args)` type of calls
  - https://github.com/j4k0xb/webcrack/issues/24
    - > optimisation ideas
    - > There are some js to c/wasm transpilers but
  - https://github.com/e9x/krunker-decompiler
    - > Krunker Decompiler
    - > Powered by webcrack
    - https://github.com/e9x/krunker-decompiler/blob/master/src/libDecompile.ts
    - https://github.com/e9x/krunker-decompiler/blob/master/src/libRenameVars.ts

### ast-grep

- https://github.com/ast-grep/ast-grep
  - > A CLI tool for code structural search, lint and rewriting. Written in Rust
  - > ast-grep is a AST-based tool to search code by pattern code. Think it as your old-friend grep but it matches AST nodes instead of text. You can write patterns as if you are writing ordinary code. It will match all code that has the same syntactical structure. You can use `$` sign + upper case letters as wildcard, e.g. `$MATCH`, to match any single AST node. Think it as REGEX dot `.`, except it is not textual.
  - https://github.com/ast-grep/ast-grep/tree/main/npm
    - > @ast-grep/cli
      > `ast-grep(sg)` is a CLI tool for code structural search, lint, and rewriting.
    - https://github.com/ast-grep/ast-grep/tree/main/crates
    - https://github.com/ast-grep/ast-grep/blob/main/benches
      - https://github.com/ast-grep/ast-grep/blob/main/benches/bench.ts#L37-L101
  - https://ast-grep.github.io/
  - https://ast-grep.github.io/playground.html
    - https://ast-grep.github.io/reference/playground.html
      - > ast-grep Playground Manual
        > The ast-grep playground is an online tool that allows you to try out ast-grep without installing anything on your machine. You can write code patterns and see how they match your code in real time. You can also apply rewrite rules to modify your code based on the patterns.
        > 
        > The playground is a great way to learn ast-grep, debug patterns/rules, report bugs and showcase ast-grep's capabilities.
  - https://ast-grep.github.io/guide/introduction.html
  - https://ast-grep.github.io/reference/languages.html
    - > List of Languages with Built-in Support
  - https://ast-grep.github.io/reference/cli.html
  - https://ast-grep.github.io/reference/api.html
    - > API Reference
      > ast-grep currently has an experimental API for Node.js
  - https://ast-grep.github.io/guide/tooling-overview.html#editor-integration
    - https://marketplace.visualstudio.com/items?itemName=ast-grep.ast-grep-vscode&ssr=false#overview
      - > ast-grep-vscode
        > VSCode extension package for ast-grep language server
  - https://github.com/ast-grep/ast-grep/issues/80
    - > Using ast-grep as a library
    - https://ast-grep.github.io/guide/api-usage/py-api.html
      - > Python API
        > `ast-grep`'s Python API is powered by PyO3. You can write Python to programmatically inspect and change syntax trees.
  - https://github.com/ast-grep/ast-grep/issues/524
    - > More powerful `tree-sitter` analysis
      - https://github.com/microsoft/vscode-anycode
        - > Anycode
          > A Tree-sitter-based language extension that inaccurately implements popular features like "Outline & Breadcrumbs", "Go to Symbol in Workspace", "Document Highlights" and more. This extension should be used when running in enviroments that don't allow for running actual language services, like https://github.dev or https://vscode.dev.
          - https://code.visualstudio.com/docs/editor/editingevolved#_go-to-symbol
          - https://microsoft.github.io/monaco-editor/typedoc/interfaces/languages.DocumentSymbolProvider.html
  - https://github.com/ast-grep/ast-grep/issues/334
    - > [pipedream] Add control flow / data dependency operators to ast-grep
    - > inspired by docs.joern.io/code-property-graph, or more specifically, docs.joern.io/cpgql/data-flow-steps
    - > State of Art:
      > 
      > * [arxiv.org/pdf/2208.07461.pdf](https://arxiv.org/pdf/2208.07461.pdf)
      >   
      >   * parser: tree-sitter
      >   * cfg/data flow: built for Python
      > * [nickgregory.me/post/2022/07/02/go-code-as-a-graph](https://nickgregory.me/post/2022/07/02/go-code-as-a-graph/)
      >   
      >   * [kallsyms/go-graph](https://github.com/kallsyms/go-graph)
      >   * parser: go
      >   * cfg/dataflow: golangx/tool
      >   * golang team's tooling is crazy...
      > * [docs.rs/tree-sitter-graph/0.10.4/tree_sitter_graph/reference](https://docs.rs/tree-sitter-graph/0.10.4/tree_sitter_graph/reference/)
      >   
      >   * parser: tree-sitter
      >   * cfg/data flow: N/A. It only supports graph construction.
      > * joern
      >   
      >   * parser: graal based. e.g. graalJS or custom parser generator
      >   * e.g. Python [joernio/joern@`7e66155`/joern-cli/frontends/pysrc2cpg/pythonGrammar.jj#L10](https://github.com/joernio/joern/blob/7e6615548fa06e94c3307da2a85709295d9f660f/joern-cli/frontends/pysrc2cpg/pythonGrammar.jj#L10)
      >   * cfg: based on a generic-ast. [joernio/joern@`7e66155`/joern-cli/frontends/x2cpg/src/main/scala/io/joern/x2cpg](https://github.com/joernio/joern/tree/7e6615548fa06e94c3307da2a85709295d9f660f/joern-cli/frontends/x2cpg/src/main/scala/io/joern/x2cpg)
      > 
      > Not related but worth looking
      > 
      > * eslint: [eslint/eslint@`main`/lib/linter/code-path-analysis/code-path-analyzer.js](https://github.com/eslint/eslint/blob/main/lib/linter/code-path-analysis/code-path-analyzer.js?rgh-link-date=2023-06-09T22%3A04%3A40Z)
      > * oxc: [Boshen/oxc@`main`/crates/oxc_semantic2/src/reference.rs](https://github.com/Boshen/oxc/blob/main/crates/oxc_semantic2/src/reference.rs?rgh-link-date=2023-06-09T22%3A04%3A40Z)
      > * ruff: [astral-sh/ruff@`main`/crates/ruff_python_semantic/src](https://github.com/astral-sh/ruff/tree/main/crates/ruff_python_semantic/src?rgh-link-date=2023-06-09T22%3A04%3A40Z)
  - https://www.reddit.com/r/rust/comments/13eg738/meet_astgrep_a_rustbased_tool_for_code_searching/

### Restringer

- https://github.com/PerimeterX/restringer
  - > Restringer
  - > Deobfuscate Javascript and reconstruct strings. Simplify cumbersome logic where possible while adhering to scope limitations.
  - https://restringer.tech/ (Playground)
  - https://github.com/PerimeterX/restringer/tree/main/src/processors
    - > Processors
      > Processors are a collection of methods meant to prepare the script for obfuscation, removing anti-debugging traps and performing any required modifications before (preprocessors) or after (postprocessors) the main deobfuscation process.
      > 
      > The processors are created when necessary and are lazily loaded when a specific obfuscation type was detected which requires these additional processes.
  - https://github.com/PerimeterX/restringer/tree/main/src/modules/safe
  - https://github.com/PerimeterX/restringer/tree/main/src/modules/unsafe
  - https://github.com/PerimeterX/obfuscation-detector
    - > Obfuscation Detector
    - > Detect different types of JS obfuscation by their AST structure.
  - https://github.com/PerimeterX/flast
    - > flAST - FLat Abstract Syntax Tree
      > Flatten an Abstract Syntax Tree by placing all the nodes in a single flat array.
    - > Provides a flat Abstract Syntax Tree and an Arborist to trim and modify the tree

### debundle + related

- https://github.com/1egoman/debundle
  - > A javascript debundler. Takes a Browserify or Webpack bundle and recreates the initial, pre-bundled source
  - https://github.com/1egoman/debundle/blob/master/DOCS.md
    - > Configuration Documentation
      > Configuration is stored in a json file with an object at its root. The headings below represent the keys in that object
  - https://github.com/1egoman/debundle/issues/23
    - > Potential reownership?
      - > I actually recently built a better version of this same tool (a much more reliable, version that requires much less configuration)
      - > I'll push up this new version to a separate, orphan branch on this repository.
      - > Here's that v2 branch: https://github.com/1egoman/debundle/tree/v2
        - > Debundle, V2
          > I needed to somewhat recently reverse engineer a few webpack bundles. I rebuilt debundle to be a bit easier to use and to do a few more things automatically. I give no support to this code right now - it's not being published on npm, any issues will be closed, etc.
          > 
          > However, I think, it's a much more streamlined way of doing things.
  - https://github.com/1egoman/debundle/issues/27
    - > Support for webpackJsonp
  - https://github.com/scil/reliable-debundle
    - > A javascript debundler. Takes a Browserify or Webpack bundle and recreates the initial, pre-bundled source
    - > forked from `1egoman/debundle`
    - > This branch is 89 commits ahead of `1egoman/debundle:master`
      - https://github.com/1egoman/debundle/compare/master...scil:reliable-debundle:master
        - https://github.com/hectorqin/debundle
          - > Modified from https://github.com/1egoman/debundle
            > 
            > The dependencies have been upgraded, some compatibility issues have been corrected, and there are other bugs, but it works and supports es6 syntax. The completeness and accuracy of the split files are not guaranteed
  - https://github.com/TheFireBlast/debundle
    - > A javascript debundler. Takes a Webpack bundle and recreates the initial, pre-bundled source.
    - > forked from `1egoman/debundle`
    - > This branch is 26 commits ahead of `1egoman/debundle:master`
      - https://github.com/1egoman/debundle/compare/master...TheFireBlast:debundle:master
- https://github.com/topics/debundle
  - https://github.com/Xmader/retidy
    - > Extract, unminify, and beautify ("retidy") each file from a webpack/parcel bundle (JavaScript reverse engineering)
  - https://github.com/nickw444/rn-debundle
    - > A very basic debundler for Javascript bundles compiled with React Native's bundler.
      > 
      > Debundles a large React Native bundle by walking the compiled AST and extracts individual module declarations and writes them to their own modules & attempts to resolve dependeny import relationships.

### joern

- https://joern.io/
  - > The Bug Hunter's Workbench
  - > Query: Uncover attack surface, sloppy coding practices, and variants of known vulnerabilities using an interactive code analysis shell. Joern supports C, C++, LLVM bitcode, x86 binaries (via Ghidra), JVM bytecode (via Soot), and Javascript. Python, Java source code, Kotlin, and PHP support coming soon.
  - > Automate: Wrap your queries into custom code scanners and share them with the community or run existing Joern-based scanners in your CI.
  - > Integrate: Use Joern as a library to power your own code analysis tools or as a component via the REST API.
  - https://github.com/joernio/joern
    - > Open-source code analysis platform for C/C++/Java/Binary/Javascript/Python/Kotlin based on code property graphs.
    - > Joern is a platform for analyzing source code, bytecode, and binary executables. It generates code property graphs (CPGs), a graph representation of code for cross-language code analysis. Code property graphs are stored in a custom graph database. This allows code to be mined using search queries formulated in a Scala-based domain-specific query language. Joern is developed with the goal of providing a useful tool for vulnerability discovery and research in static program analysis.
  - https://docs.joern.io/
    - > Joern is a platform for robust analysis of source code, bytecode, and binary code. It generates code property graphs, a graph representation of code for cross-language code analysis. Code property graphs are stored in a custom graph database. This allows code to be mined using search queries formulated in a Scala-based domain-specific query language. Joern is developed with the goal of providing a useful tool for vulnerability discovery and research in static program analysis.
    - > The core features of Joern are:
      > - Robust parsing. Joern allows importing code even if a working build environment cannot be supplied or parts of the code are missing.
      > - Code Property Graphs. Joern creates semantic code property graphs from the fuzzy parser output and stores them in an in-memory graph database. SCPGs are a language-agnostic intermediate representation of code designed for query-based code analysis.
      > - Taint Analysis. Joern provides a taint-analysis engine that allows the propagation of attacker-controlled data in the code to be analyzed statically.
      > - Search Queries. Joern offers a strongly-typed Scala-based extensible query language for code analysis based on Gremlin-Scala. This language can be used to manually formulate search queries for vulnerabilities as well as automatically infer them using machine learning techniques.
      > - Extendable via CPG passes. Code property graphs are multi-layered, offering information about code on different levels of abstraction. Joern comes with many default passes, but also allows users to add passes to include additional information in the graph, and extend the query language accordingly.
    - https://docs.joern.io/code-property-graph/
    - https://docs.joern.io/cpgql/data-flow-steps/
    - https://docs.joern.io/export/
      - > Joern can create the following graph representations for C/C++ code:
        > - Abstract Syntax Trees (AST)
        > - Control Flow Graphs (CFG)
        > - Control Dependence Graphs (CDG)
        > - Data Dependence Graphs (DDG)
        > - Program Dependence graphs (PDG)
        > - Code Property Graphs (CPG14)
        > - Entire graph, i.e. convert to a different graph format (ALL)
- https://en.wikipedia.org/wiki/Code_property_graph
  - > A code property graph of a program is a graph representation of the program obtained by merging its [abstract syntax trees](https://en.wikipedia.org/wiki/Abstract_syntax_tree) (AST), [control-flow graphs](https://en.wikipedia.org/wiki/Control-flow_graph) (CFG) and [program dependence graphs](https://en.wikipedia.org/wiki/Program_dependence_graph) (PDG) at statement and predicate nodes. The resulting graph is a property graph, which is the underlying graph model of [graph databases](https://en.wikipedia.org/wiki/Graph_database) such as [Neo4j](https://en.wikipedia.org/wiki/Neo4j), [JanusGraph](https://en.wikipedia.org/wiki/JanusGraph) and [OrientDB](https://en.wikipedia.org/wiki/OrientDB) where data is stored in the nodes and edges as [key-value pairs](https://en.wikipedia.org/wiki/Key-value_pair). In effect, code property graphs can be stored in graph databases and queried using graph query languages.
  - > Joern CPG. The original code property graph was implemented for C/C++ in 2013 at University of Göttingen as part of the open-source code analysis tool Joern. This original version has been discontinued and superseded by the open-source Joern Project, which provides a formal code property graph specification applicable to multiple programming languages. The project provides code property graph generators for C/C++, Java, Java bytecode, Kotlin, Python, JavaScript, TypeScript, LLVM bitcode, and x86 binaries (via the Ghidra disassembler).
    - https://github.com/joernio/joern
      - > Open-source code analysis platform for C/C++/Java/Binary/Javascript/Python/Kotlin based on code property graphs.
      - > Joern is a platform for analyzing source code, bytecode, and binary executables. It generates code property graphs (CPGs), a graph representation of code for cross-language code analysis. Code property graphs are stored in a custom graph database. This allows code to be mined using search queries formulated in a Scala-based domain-specific query language. Joern is developed with the goal of providing a useful tool for vulnerability discovery and research in static program analysis.
      - https://joern.io/
      - https://cpg.joern.io/
        - > Code Property Graph Specification 1.1
        - > This is the specification of the Code Property Graph, a language-agnostic intermediate graph representation of code designed for code querying.
          > 
          > The code property graph is a directed, edge-labeled, attributed multigraph. This specification provides the graph schema, that is, the types of nodes and edges and their properties, as well as constraints that specify which source and destination nodes are permitted for each edge type.
          > 
          > The graph schema is structured into multiple layers, each of which provide node, property, and edge type definitions. A layer may depend on multiple other layers and make use of the types it provides.

## Blogs / Articles / etc

- https://thejunkland.com/blog/using-llms-to-reverse-javascript-minification.html
  - > Using LLMs to reverse JavaScript variable name minification
  - > This blog introduces a novel way to reverse minified Javascript using large language models (LLMs) like ChatGPT and llama2 while keeping the code semantically intact. The code is open source and available at Github project Humanify
    - https://github.com/jehna/humanify
      - > Un-minify Javascript code using ChatGPT
      - > This tool uses large language modeles (like ChatGPT & llama2) and other tools to un-minify Javascript code. Note that LLMs don't perform any structural changes – they only provide hints to rename variables and functions. The heavy lifting is done by Babel on AST level to ensure code stays 1-1 equivalent.
      - https://github.com/jehna/humanify/issues/3
        - > Consider using `pionxzh/wakaru` instead of/alongside `webcrack`
      - https://github.com/jehna/humanify/blob/main/src/index.ts
      - https://github.com/jehna/humanify/blob/main/src/humanify.ts
      - https://github.com/jehna/humanify/blob/main/src/openai/openai.ts#L28-L82
      - https://github.com/jehna/humanify/blob/main/src/openai/rename-variables-and-functions.ts#L9-L26
      - https://github.com/jehna/humanify/blob/main/src/openai/is-reserved-word.ts1
      - https://github.com/jehna/humanify/blob/main/src/local-rename.ts
        - https://github.com/jehna/humanify/blob/main/src/mq.ts
        - https://github.com/jehna/humanify/tree/main/local-inference
        - https://github.com/jehna/humanify/blob/main/local-inference/inference-server.py
        - https://github.com/jehna/humanify/blob/main/local-inference/rename.py
- https://blog.apify.com/chatgpt-reverse-engineer-code/
  - > Unlocking JavaScript secrets: reverse engineering code with ChatGPT
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/code-review-tools#static-analysis
  - https://github.com/carlospolop/hacktricks/issues/743
    - > Some useful tool additions for 'Code Review Tools -> JavaScript -> Static Analysis -> Deobfuscate/Unpack'
- https://www.digitalocean.com/community/tutorials/js-traversing-ast
- https://medium.com/@yuexing0921/a-brief-introduction-of-various-javascript-parsers-103e32c4d7d2
- https://jotadeveloper.medium.com/abstract-syntax-trees-on-javascript-534e33361fc7
- https://infosecwriteups.com/javascript-parser-to-create-abstract-syntax-tree-ast-acorn-be9bbfe91bed
- https://itnext.io/ast-for-javascript-developers-3e79aeb08343
- https://steakenthusiast.github.io/
  - > Learning Reverse Engineering by Example
  - https://steakenthusiast.github.io/2022/05/21/Deobfuscating-Javascript-via-AST-An-Introduction-to-Babel/
    - > An Introduction to Javascript Obfuscation & Babel
  - https://steakenthusiast.github.io/2022/05/22/Deobfuscating-Javascript-via-AST-Manipulation-Various-String-Concealing-Techniques/
    - > Deobfuscating Javascript via AST: Reversing Various String Concealing Techniques
  - https://steakenthusiast.github.io/2022/05/28/Deobfuscating-Javascript-via-AST-Manipulation-Converting-Bracket-Notation-Dot-Notation-for-Property-Accessors/
    - > Deobfuscating Javascript via AST: Converting Bracket Notation => Dot Notation for Property Accessors
  - https://steakenthusiast.github.io/2022/05/28/Deobfuscating-Javascript-via-AST-Manipulation-Constant-Folding/
    - > Deobfuscating Javascript via AST: Constant Folding/Binary Expression Simplification
  - https://steakenthusiast.github.io/2022/05/31/Deobfuscating-Javascript-via-AST-Replacing-References-to-Constant-Variables-with-Their-Actual-Value/
    - > Deobfuscating Javascript via AST: Replacing References to Constant Variables with Their Actual Value
  - https://steakenthusiast.github.io/2022/06/04/Deobfuscating-Javascript-via-AST-Removing-Dead-or-Unreachable-Code/
    - > Deobfuscating Javascript via AST: Removing Dead or Unreachable Code
  - https://steakenthusiast.github.io/2022/06/14/Deobfuscating-Javascript-via-AST-Deobfuscating-a-Peculiar-JSFuck-style-Case/
    - > Deobfuscating Javascript via AST: A Peculiar JSFuck-esque Case
- https://www.trickster.dev/post/
  - > Trickster Dev: Code level discussion of web scraping, gray hat automation, growth hacking and bounty hunting
  - https://www.trickster.dev/post/understanding-abstract-syntax-trees/
    - > Understanding Abstract Syntax Trees
  - https://www.trickster.dev/post/javascript-obfuscation-techniques-by-example/
    - > Javascript obfuscation techniques by example
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-the-first-steps/
    - > JavaScript AST manipulation with Babel: the first steps
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-extracting-hardcoded-data/
    - > JavaScript AST manipulation with Babel: extracting hardcoded data
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-removing-unreachable-code/
    - > JavaScript AST manipulation with Babel: removing unreachable code
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-defeating-string-array-mapping/
    - > JavaScript AST manipulation with Babel: defeating string array mapping
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-transform-prototyping-and-plugin-development/
    - > JavaScript AST manipulation with Babel: transform prototyping and plugin development
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-3-ways-to-create-nodes-and-subtrees/
    - > JavaScript AST manipulation with Babel: 3 ways to create nodes and subtrees
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-untangling-scope-confusion/
    - > JavaScript AST manipulation with Babel: untangling scope confusion
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-ast-modification-apis/
    - > JavaScript AST manipulation with Babel: AST modification APIs
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-constant-folding-and-propagation/
    - > JavaScript AST manipulation with Babel: constant folding and propagation
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-reducing-indirection-undoing-string-concealing/
    - > JavaScript AST manipulation with Babel: reducing indirection, undoing string concealing
  - https://www.trickster.dev/post/javascript-ast-manipulation-with-babel-reducing-nestedness-unflattening-the-cfg/
    - > JavaScript AST manipulation with Babel: reducing nestedness, unflattening the CFG
  - https://www.trickster.dev/post/dont-jsfuck-with-me-part-1/
    - > Don’t JSFuck with me: Part 1
  - https://www.trickster.dev/post/dont-jsfuck-with-me-part-2/
    - > Don’t JSFuck with me: Part 2
  - https://www.trickster.dev/post/dont-jsfuck-with-me-part-3/
    - > Don’t JSFuck with me: Part 3
  - https://www.trickster.dev/post/understanding-javascript-packers/
    - > Understanding JavaScript packers
  - https://www.trickster.dev/post/self-defending-js-code-and-debugger-traps/
    - > Self-defending JS code and debugger traps
  - https://www.trickster.dev/post/restringer-modular-javascript-deobfuscator/
    - > Restringer: modular JavaScript deobfuscator
  - https://www.trickster.dev/post/solving-a-simple-js-challenge-with-sandboxing/
    - > Solving a simple JS challenge with sandboxing
- https://raz0r.name/articles/using-codeql-to-detect-client-side-vulnerabilities-in-web-applications/
  - > Using CodeQL to detect client-side vulnerabilities in web applications

## Libraries / Helpers

### Unsorted

- https://astexplorer.net/
  - https://github.com/fkling/astexplorer
    - > A web tool to explore the ASTs generated by various parsers.
    - https://github.com/fkling/astexplorer/tree/master/website
      - Seems to be written in React, which is nice!
    - https://github.com/fkling/astexplorer/issues/625
      - > State of the Project
    - https://github.com/fkling/astexplorer/issues/304
      - > Path to astexplorer v3
    - https://github.com/fkling/astexplorer/issues/70
      - > Make astexplorer standalone / embeddable
    - https://github.com/fkling/astexplorer/issues/646
      - > Any plans to encapsulate parsers as NPM package?
    - https://github.com/fkling/astexplorer/issues/510
      - > Feature request: Tree of JavaScript scopes (`eslint-scope`)
    - https://github.com/fkling/astexplorer/issues/310
      - > Show JSON path
    - https://github.com/fkling/astexplorer/issues/688
      - > Add support for `semantic` / `tree-sitter`
      - https://github.com/fkling/astexplorer/issues/622
        - > feat: `web-tree-sitter`
- https://github.com/sxzz/ast-explorer
  - > AST Explorer - For most popular front-end languages and parsers
  - https://ast.sxzz.moe/
- https://github.com/dsherret/ts-ast-viewer
  - > TypeScript AST viewer
  - https://ts-ast-viewer.com/
- https://github.com/rajasegar/ast-builder
  - > Build your ASTs directly from code
  - > Build your Abstract Syntax Trees (AST) directly by writing code. Simply type in your code and get the right jscodeshift api to build your AST.
  - > WARNING: This repository is moved here https://github.com/rajasegar/ast-tooling/tree/master/apps/ast-builder
  - https://github.com/rajasegar/ast-tooling/tree/master/packages/ast-node-builder
  - https://www.hangaroundtheweb.com/posts/ast-builder-building-ast-nodes-from-code/
    - > AST Builder - Building AST nodes from code
- https://github.com/estree/estree
  - > The ESTree Spec
- https://github.com/jquery/esprima
  - > ECMAScript parsing infrastructure for multipurpose analysis
- https://github.com/eslint/espree
  - > An Esprima-compatible JavaScript parser
  - > Espree started out as a fork of Esprima v1.2.2, the last stable published released of Esprima before work on ECMAScript 6 began. Espree is now built on top of Acorn, which has a modular architecture that allows extension of core functionality. The goal of Espree is to produce output that is similar to Esprima with a similar API so that it can be used in place of Esprima.
  - > The primary goal is to produce the exact same AST structure and tokens as Esprima, and that takes precedence over anything else. (The AST structure being the ESTree API with JSX extensions.) Separate from that, Espree may deviate from what Esprima outputs in terms of where and how comments are attached, as well as what additional information is available on AST nodes. That is to say, Espree may add more things to the AST nodes than Esprima does but the overall AST structure produced will be the same.
    > 
    > Espree may also deviate from Esprima in the interface it exposes.
- https://github.com/eslint/eslint-scope
  - > `eslint-scope`: ECMAScript scope analyzer
  - > ESLint Scope is the ECMAScript scope analyzer used in ESLint. It is a fork of `escope`.
  - https://github.com/MarcosNASA/telEScope
    - > TelEScope.js is the first part of the «3 pilars project» inspired by Kyle Simpson
    - > Parses scopes (from `eslint-scope`) into a data structure that allows building scope chain visualization tools
      - https://github.com/MarcosNASA/bubbl.es
        - > Bubbl.es is the first part of the «3 pilars project» inspired by Kyle Simpson
        - > Visualize the JS scope chain as colored bubbles. Powered by `telEScope`
        - https://jsbubbl.es/
        - https://jsbubbl.es/theory
        - https://jsbubbl.es/bubbles
- https://github.com/acornjs/acorn
  - > A tiny, fast JavaScript parser, written completely in JavaScript
- https://github.com/acornjs/acorn-jsx
  - > Alternative, faster React.js JSX parser
- https://github.com/davidbonnet/astring
  - > Tiny and fast JavaScript code generator from an ESTree-compliant AST
- https://github.com/goto-bus-stop/estree-assign-parent
  - > assign `.parent` properties to all nodes in an AST
- https://github.com/goto-bus-stop/scope-analyzer
  - > simple scope analysis for javascript ASTs. tracks scopes and collects references to variables.
- https://github.com/afiore/arboreal
  - > Javascript tree-traversal and manipulation microlibrary
  - > This repository has been archived by the owner on Apr 4, 2020. It is now read-only.
  - https://github.com/shonzilla/arboreal
    - https://github.com/afiore/arboreal/compare/master...shonzilla:arboreal:master
- https://github.com/coderaiser/putout
  - > Pluggable and configurable JavaScript Linter and code transformer with built-in ESLint and Babel support for js, jsx typescript, flow, markdown, yaml and json. Write declarative codemods in a simplest possible way
  - > Putout is JavaScript Linter, pluggable and configurable code transformer based on Babel with built-in ESLint. It has a lot of transformations that keeps your codebase in a clean state, removing any code smell and making code readable according to best practices.
  - https://github.com/coderaiser/putout#-built-in-transformations
- https://codsen.com/os/#ast-libraries
  - > AST Libraries
    > - `ast-compare`: Compare anything: AST, objects, arrays, strings and nested thereof
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-compare
    > - `ast-contains-only-empty-space`: Does AST contain only empty space?
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-contains-only-empty-space
    > - `ast-deep-contains`: Like t.same assert on array of objects, where element order doesn’t matter.
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-deep-contains
    > - `ast-delete-object`: Delete all plain objects in AST if they contain a certain key/value pair
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-delete-object
    > - `ast-get-object`: Getter/setter for nested parsed HTML AST’s, querying objects by key/value pairs
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-get-object
    > - `ast-get-values-by-key`: Extract values and paths from AST by keys OR set them by keys
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-get-values-by-key
    > - `ast-is-empty`: Find out, is nested array/object/string/AST tree is empty
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-is-empty
    > - `ast-loose-compare`: Compare anything: AST, objects, arrays and strings
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-loose-compare
    > - `ast-monkey`: Traverse and edit AST
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-monkey
    > - `ast-monkey-traverse`: Utility library to traverse AST
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-monkey-traverse
    > - `ast-monkey-traverse-with-lookahead`: Utility library to traverse AST, reports upcoming values
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-monkey-traverse-with-lookahead
    > - `ast-monkey-util`: Utility library of AST helper functions
    >   - https://github.com/codsen/codsen/tree/main/packages/ast-monkey-util
  - https://github.com/codsen/codsen
    - > a monorepo of npm packages
    - > Please visit codsen.com for an overview and full documentation of all packages
    - https://github.com/codsen/codsen/tree/main/packages
- https://github.com/scottrogowski/code2flow
  - > Pretty good call graphs for dynamic languages
  - > Code2flow generates call graphs for dynamic programming language. Code2flow supports Python, JavaScript, Ruby, and PHP.
    > 
    > The basic algorithm is simple:
    > - Translate your source files into ASTs.
    > - Find all function definitions.
    > - Determine where those functions are called.
    > - Connect the dots.
    > 
    > Code2flow is useful for:
    > - Untangling spaghetti code.
    > - Identifying orphaned functions.
    > - Getting new developers up to speed.
    > 
    > Code2flow provides a pretty good estimate of your project's structure. No algorithm can generate a perfect call graph for a dynamic language – even less so if that language is duck-typed. See the known limitations in the section below.
  - https://github.com/scottrogowski/code2flow#known-limitations
  - https://github.com/scottrogowski/code2flow#why-is-it-impossible-to-generate-a-perfect-call-graph
    - Though in that toy example instance.. we could attempt to capture/output the possible states/differences/conditions/etc that could be achieved.. if this doesn't already handle it
- https://github.com/Persper/js-callgraph
  - > Construct approximate static call graph for JavaScript & Typescript
  - > This project implements a field-based call graph construction algorithm for JavaScript as described in
    > > A. Feldthaus, M. Schäfer, M. Sridharan, J. Dolby, F. Tip. Efficient Construction of Approximate Call Graphs for JavaScript IDE Services. In ICSE, 2013.
    > This repo builds upon Max Schaefer's original `acg.js`
    - https://github.com/xiemaisi/acg.js
- https://github.com/whyboris/TypeScript-Call-Graph
  - > CLI to generate an interactive graph of functions and calls from your TypeScript files
  - https://github.com/Deskbot/TS-Call-Graph
    - > A program that generates a graph of the methods and attributes of a TypeScript class
- https://github.com/julianjensen/ast-flow-graph
  - > ast-flow-graph
  - > Creates a CFG from JavaScript source code.
  - > This module will read one or more JavaScript source files and produce CFGs (Control Flow Graphs) of the code.
  - Uses espree, escope, estraverse, etc
  - https://github.com/isaacs/yallist
    - > Yet Another Linked List
      > 
      > There are many doubly-linked list implementations like it, but this one is mine.
      > 
      > For when an array would be too big, and a Map can't be iterated in reverse order.
  - https://github.com/julianjensen/traversals
    - > Small module for graph traversals, supporting DFS and BFS with niceties added for pre- and post-order, including their reverses.
    - Some notes from ChatGPT:
      - > Provides a small module designed for performing graph traversal operations, specifically Depth-First Search (DFS) and Breadth-First Search (BFS). It includes additional features such as pre-order and post-order traversals, as well as their reverse versions, to enhance the functionality of these standard graph traversal techniques.
  - https://github.com/julianjensen/dominators
    - > Various dominator tree algorithms
    - > It implements two different methods for finding the immediate dominators of a graph.
    - Some notes from ChatGPT:
      - > A dominator tree is a concept used in computer science, particularly in the field of compiler design and program analysis. To understand a dominator tree, let's first look at the concept of dominators in a control flow graph (CFG).
        > 
        > In a CFG, which represents the flow of control in a program, a node \( A \) is said to dominate another node \( B \) if every path from the start node of the graph to \( B \) must go through \( A \). In other words, \( A \) dominates \( B \) if \( A \) is always encountered before \( B \) when traversing the graph from the start node.
        > 
        > The concept becomes more nuanced with the idea of immediate dominators. An immediate dominator of a node \( B \) is the last dominator on any path from the start node to \( B \). 
        > 
        > Now, a dominator tree is a tree structure that represents these dominance relationships within a CFG. In this tree:
        > 
        > - Each node corresponds to a node in the original CFG.
        > - There is a directed edge from node \( A \) to node \( B \) if \( A \) is the immediate dominator of \( B \) in the CFG.
        > 
        > A dominator tree generator, therefore, is a tool or an algorithm that constructs the dominator tree from a given control flow graph. This tool is essential in optimizing compilers and in various program analysis tasks, where understanding the dominance relationships helps in transformations like loop optimization, dead code elimination, and more sophisticated analyses like static single assignment (SSA) form conversion.
        > 
        > This concept is closely related to computer science and software engineering, particularly in areas concerning compiler construction and code optimization. Given your background in software engineering and ethical hacking, this knowledge could be particularly useful in understanding code structure and flow, especially when analyzing or optimizing complex software systems.
- https://github.com/ojj11/analyse-control
  - > Analyse-Control
  - > Control flow analysis for JavaScript
  - > Extract the control flow graph from a script. Control flow refers to what order a set of instructions execute in. By using conditional statements and loops, the order of a set of instructions can be changed. This library extracts all possible execution flows through a script as a graph of nodes.
- https://twitter.com/_devalias/status/1776163243381440831
  - > Glenn 'devalias' Grant @_devalias
    > Curious, is anyone aware of any tools for creating Control Flow Graphs (CFG) / similar from `tree-sitter` output?
    > 
    > Ideally in a way that is generic / abstract enough to apply to any parseable language (maybe via queries/tags? https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries )
  - > I had a bit of a cursory search, but didn't come across anything that seemed like it did it.
    >
    > This was my ChatGPT convo / musings on how it might be able to be implemented: https://chat.openai.com/share/e9226daa-af14-4702-a9c2-f56d1c94b61c
  - > https://en.wikipedia.org/wiki/Control-flow_graph
    > 
    > https://en.wikipedia.org/wiki/Control_flow_analysis
  - > https://tree-sitter.github.io/tree-sitter/code-navigation-systems
  - > This would potentially be a useful library: https://github.com/tree-sitter/tree-sitter-graph
- https://github.com/dochne/wappalyzer
  - > Wappalyzer identifies technologies on websites, such as CMS, web frameworks, ecommerce platforms, JavaScript libraries, analytics tools and more.
  - > The last commit of Wappalyzer before it went private
  - > Specification
    > A long list of regular expressions is used to identify technologies on web pages. Wappalyzer inspects HTML code, as well as JavaScript variables, response headers and more.
    > Patterns (regular expressions) are kept in `src/technologies/`
    - https://github.com/dochne/wappalyzer/tree/main/src/technologies
    - https://github.com/dochne/wappalyzer/blob/main/src/groups.json
    - https://github.com/dochne/wappalyzer/blob/main/src/categories.json
    - https://github.com/dochne/wappalyzer/blob/471c2fb0b093973c098bd1855b89c8cde4997479/src/js/index.js#L133
      - Loads all of the technologies `.json` files: ```chrome.runtime.getURL(`technologies/${character}.json`)```
      - Deletes some keys from the loaded data:
        - ```js
          Object.keys(technologies).forEach((name) => {
            delete technologies[name].description
            delete technologies[name].cpe
            delete technologies[name].pricing
            delete technologies[name].website
          })
          ```
      - calls `setTechnologies(technologies)`
        - https://github.com/dochne/wappalyzer/blob/471c2fb0b093973c098bd1855b89c8cde4997479/src/js/wappalyzer.js#L348-L425
          - Re-maps a bunch of the `.json` keys to different in-memory names/etc
      - `analyzeJs`: Analyse JavaScript variables
      - `analyzeDom`: Analyse DOM nodes
      - `analyzeManyToMany`
        - ```js
          Object.keys(technology[type]).reduce((technologies, key) => {
            const patterns = technology[type][key] || []
            const values = items[key] || []

            patterns.forEach((_pattern) => {
              const pattern = (subtypes || []).reduce(
                (pattern, subtype) => pattern[subtype] || {},
                _pattern
              )

              values.forEach((value) => {
                const startTime = Date.now()

                const matches = pattern.regex.exec(value)

                if (matches) {
                  technologies.push({
          ```
    - We could download and filter these `.json` files to find the `js` patterns used similar to this:
      - ```shell
        ⇒ wget https://github.com/dochne/wappalyzer/raw/main/src/technologies/a.json
        
        ⇒ jq 'to_entries | map(select(.value.js != null) | {key: .key, value: .value.js}) | from_entries' a.json
        
        # ..snip..
        #
        #  "anime.js": {
        #    "anime.version": "^([\\d\\.]+)$\\;version:\\1"
        #  },
        #  "authorize.net": {
        #    "config.authorizenet_public_client_key": ""
        #  }
        #}
        ```
- https://github.com/lebab/lebab
  - > Turn your ES5 code into readable ES6. Lebab does the opposite of what Babel does.
  - > Lebab transpiles your ES5 code to ES6/ES7. It does exactly the opposite of what Babel does.
  - https://lebab.github.io/ (Playground)
- https://github.com/EricSmekens/jsep
  - > `jsep`: A Tiny JavaScript Expression Parser
    > `jsep` is a simple expression parser written in JavaScript. It can parse JavaScript expressions but not operations. The difference between expressions and operations is akin to the difference between a cell in an Excel spreadsheet vs. a proper JavaScript program.
  - https://ericsmekens.github.io/jsep/
- https://github.com/oxc-project/oxc
  - > Oxc
    > The Oxidation Compiler is creating a suite of high-performance tools for JavaScript and TypeScript.
    > 
    > Oxc is building a parser, linter, formatter, transpiler, minifier, resolver ... all written in Rust.
  - https://github.com/oxc-project/oxc#-ast-and-parser
    - > AST and Parser
      > Oxc maintains its own AST and parser, which is by far the fastest and most conformant JavaScript and TypeScript (including JSX and TSX) parser written in Rust.
    - > While many existing JavaScript tools rely on [estree](https://github.com/estree/estree) as their AST specification, a notable drawback is its abundance of ambiguous nodes. This ambiguity often leads to confusion during development with [estree](https://github.com/estree/estree).
      > 
      > The Oxc AST differs slightly from the [estree](https://github.com/estree/estree) AST by removing ambiguous nodes and introducing distinct types. For example, instead of using a generic [estree](https://github.com/estree/estree) `Identifier`, the Oxc AST provides specific types such as `BindingIdentifier`, `IdentifierReference`, and `IdentifierName`. This clear distinction greatly enhances the development experience by aligning more closely with the ECMAScript specification.
  - https://oxc-project.github.io/
    - https://oxc-project.github.io/oxc/playground/
    - https://oxc-project.github.io/docs/guide/usage/parser.html
    - > Parser
      > - 2x faster then [SWC](https://swc.rs/) parser
      > - By far the fastest and most conformant JavaScript and TypeScript (including JSX and TSX) parser written in Rust
      - https://github.com/oxc-project/bench-javascript-parser-written-in-rust
        - > Benchmark for Oxc, Swc and Rome parser
    - > The umbrella crate [`oxc`](https://docs.rs/oxc) exports all public crates from this repository
    - > The AST and parser crates [`oxc_ast`](https://docs.rs/oxc_ast) and [`oxc_parser`](https://docs.rs/oxc_parser) are production ready
      - https://docs.rs/oxc_parser/latest/oxc_parser/#conformance
        - > The parser parses all of Test262 and most of Babel and TypeScript parser conformance tests.
          - https://github.com/oxc-project/oxc/tree/main/tasks/coverage
  - https://oxc-project.github.io/javascript-parser-in-rust/
    - > Write a JavaScript Parser in Rust
      >
      > Rust, JavaScript, and parsers are all hard to learn, let's combine these three and challenge ourselves to write a JavaScript parser in Rust.
      > 
      > This will be the guide for you if you are interested in learning Rust, parsers, or would like to contribute to [oxc](https://github.com/boshen/oxc), [swc](https://swc.rs/) or [Biome](https://biomejs.dev/) in the near future.
      > 
      > The guide will cover all the basic topics of writing a JavaScript parser in rust. The tutorials will explain some topics in more depth.
    - https://oxc-project.github.io/javascript-parser-in-rust/blog/
      - https://oxc-project.github.io/javascript-parser-in-rust/blog/rome/
        - > Rome Tools
          > Rome uses a different set of techniques for parsing JavaScript and TypeScript. This tutorial summarizes them in learning order for better understanding.
        - > The Rome codebase was rewritten from TypeScript to Rust, see Rome will be rewritten in Rust
          > The decision was made after talking to the author of `rslint` and `rust-analyzer`
          > `rust-analyzer` proved that IDE-centric tools built around concrete syntax tree are possible
          > `rslint` proved that it is possible to write a JavaScript parser in Rust, with the same base libraries as rust-analyzer
        - > The base library is called [rowan](https://github.com/rust-analyzer/rowan), see [overview of rowan](https://github.com/rust-lang/rust-analyzer/blob/master/docs/dev/syntax.md)
          > Rowan, also known as red-green trees, is named after the real green [rowan tree](https://en.wikipedia.org/wiki/Rowan) that makes red berries
          > The origin of red-green trees is described in this [blog post](https://ericlippert.com/2012/06/08/red-green-trees/), by the authors of the C# programming language
          > The whole point of rowan is to define a lossless concrete syntax tree (CST) that describes all the details of the source code and provides a set of traversal APIs (parent, children, siblings, etc)
          > Read the advantage of having a CST over an AST: [Pure AST based linting sucks](https://rdambrosio016.github.io/rust/2020/09/18/pure-ast-based-linting-sucks.html)
          > CST provides the ability to build a fully recoverable parser
  - https://craftinginterpreters.com/
    - > Ever wanted to make your own programming language or wondered how they are designed and built? If so, this book is for you.
    - > Crafting Interpreters contains everything you need to implement a full-featured, efficient scripting language. You’ll learn both high-level concepts around parsing and semantics and gritty details like bytecode representation and garbage collection. Your brain will light up with new ideas, and your hands will get dirty and calloused. It’s a blast.
      > 
      > Starting from `main()`, you build a language that features rich syntax, dynamic typing, garbage collection, lexical scope, first-class functions, closures, classes, and inheritance. All packed into a few thousand lines of clean, fast code that you thoroughly understand because you write each one yourself.
- https://github.com/kaleidawave/ezno
  - > A JavaScript compiler and TypeScript checker written in Rust with a focus on static analysis and runtime performance
  - https://kaleidawave.github.io/posts/introducing-ezno/
    - > Introducing Ezno
    - > Ezno is an experimental compiler I have been working on and off for a while. In short, it is a JavaScript compiler featuring checking, correctness and performance for building full-stack (rendering on the client and server) websites.
  - https://kaleidawave.github.io/posts/ezno-23/
    - > Ezno in '23
- https://github.com/boa-dev/boa
  - > Boa is an embeddable and experimental Javascript engine written in Rust. Currently, it has support for some of the language.
  - > This is an experimental Javascript lexer, parser and interpreter written in Rust. Currently, it has support for some of the language.
  - https://boajs.dev/
    - > Boa is an experimental Javascript lexer, parser and compiler written in Rust. Currently, it has support for some of the language. It can be embedded in Rust projects fairly easily and also used from the command line. Boa also exists to serve as a Rust implementation of the EcmaScript specification, there will be areas where we can utilise Rust and its fantastic ecosystem to make a fast, concurrent and safe engine.
    - https://boajs.dev/boa/playground/
    - https://boajs.dev/posts/2022-10-24-boa-usage/
      - > Adding a JavaScript interpreter to your Rust project
    - https://boajs.dev/boa/dev/bench/
      - > Boa Benchmarks
      - https://github.com/boa-dev/boa/blob/main/boa_engine/benches/full.rs#L9
        - https://github.com/bheisler/criterion.rs
          - > Statistics-driven benchmarking library for Rust
          - > Criterion.rs helps you write fast code by detecting and measuring performance improvements or regressions, even small ones, quickly and accurately. You can optimize with confidence, knowing how each change affects the performance of your code.
          - https://docs.rs/criterion/latest/criterion/
    - https://boajs.dev/boa/test262/
      - > EcmaScript conformance test results for Boa
- https://github.com/rust-analyzer/rowan
  - > Rowan is a library for lossless syntax trees, inspired in part by Swift's libsyntax.
- https://github.com/mozilla-spidermonkey/jsparagus
  - > Experimental JS parser-generator project.
  - > jsparagus - A JavaScript parser written in Rust
    > jsparagus is intended to replace the JavaScript parser in Firefox.
  - https://github.com/mozilla-spidermonkey/jsparagus#benchmarking
    - > Benchmarking
  - https://github.com/mozilla-spidermonkey/jsparagus#limitations
    - > Limitations
- https://github.com/ratel-rust/ratel-core
  - > High performance JavaScript to JavaScript compiler with a Rust core
  - https://maciej.codes/ratel-wasm/ (REPL / Playground)
  - https://github.com/ratel-rust/ratel-cli
    - > A command-line interface for Ratel, a high performance JavaScript to JavaScript compiler with a Rust core

### Recast + related

- https://github.com/benjamn/recast
  - > JavaScript syntax tree transformer, nondestructive pretty-printer, and automatic source map generator
  - https://github.com/benjamn/recast/blob/master/lib/options.ts
    - > All Recast API functions take second parameter with configuration options, documented in `options.js`
  - https://github.com/benjamn/recast/tree/master/parsers
    - `acorn`, `babel-ts`, `babel`, `babylon`, `esprima`, `flow`, `typescript`
  - https://github.com/benjamn/ast-types
    - > Esprima-compatible implementation of the Mozilla JS Parser API
    - https://github.com/benjamn/ast-types#ast-traversal
      - > AST Traversal
        > Because it understands the AST type system so thoroughly, this library is able to provide excellent node iteration and traversal mechanisms.
    - https://github.com/benjamn/ast-types#nodepath
      - > `NodePath`
        > The `NodePath` object passed to visitor methods is a wrapper around an AST node, and it serves to provide access to the chain of ancestor objects (all the way back to the root of the AST) and scope information.
    - https://github.com/benjamn/ast-types#scope
      - > Scope
        > The object exposed as `path.scope` during AST traversals provides information about variable and function declarations in the scope that contains path.node. See `scope.ts` for its public interface, which currently includes `.isGlobal`, `.getGlobalScope()`, `.depth`, `.declares(name)`, `.lookup(name)`, and `.getBindings()`
        - https://github.com/benjamn/ast-types/blob/master/src/scope.ts
    - https://github.com/benjamn/ast-types#custom-ast-node-types
      - > Custom AST Node Types
        > The `ast-types` module was designed to be extended. To that end, it provides a readable, declarative syntax for specifying new AST node types, based primarily upon the `require("ast-types").Type.def` function
      - > The def syntax is used to define all the default AST node types found in `babel-core.ts`, `babel.ts`, `core.ts`, `es-proposals.ts`, `es6.ts`, `es7.ts`, `es2020.ts`, `esprima.ts`, `flow.ts`, `jsx.ts`, `type-annotations.ts`, and `typescript.ts`, so you have no shortage of examples to learn from.
        - https://github.com/benjamn/ast-types/tree/master/src/def
          - `babel-core.ts`, `babel.ts`, `core.ts`, `es-proposals.ts`, `es2016.ts`, `es2017.ts`, `es2018.ts`, `es2019.ts`, `es2020.ts`, `es2021.ts`, `es2022.ts`, `es6.ts`, `esprima.ts`, `flow.ts`, `jsx.ts`, `type-annotations.ts`, `typescript.ts`
          - `operators/`: `core.ts`, `es2016.ts`, `es2020.ts`, `es2021.ts`
- https://github.com/facebook/jscodeshift
  - > A JavaScript codemod toolkit
  - > jscodeshift is a toolkit for running codemods over multiple JavaScript or TypeScript files. It provides:
    > - A runner, which executes the provided transform for each file passed to it. It also outputs a summary of how many files have (not) been transformed.
    > - A wrapper around recast, providing a different API. Recast is an AST-to-AST transform tool and also tries to preserve the style of original code as much as possible.
   - https://github.com/facebook/jscodeshift/issues/500
     - > Bringing jscodeshift up to date
     - > The biggest issue is with recast. This library hasn't really had a lot of maintenance for the last couple of years, and there's something like 150+ issues and 40+ pull requests waiting to be merged. It seems like 80% of the issues that are logged against jscodeshift are actually recast issues. In order to fix the jscodeshift's outstanding issues, either recast itself needs to fix them or jscodeshift will need to adopt/create its own fork of recast to solve them. For the past year and a half or so putout's main developer has been maintaining a fork of recast and adding a lot of fixes to it. It might be worthwhile to look at switching to @putout/recast as opposed to the recast upstream. I've also been working on a fork of @putout/recast for evcodeshift that adds a few other things to make evcodeshift transforms more debuggable in vscode.
     - https://github.com/putoutjs/recast
       - https://github.com/putoutjs/printer
       - > Prints Babel AST to readable JavaScript. For ESTree use estree-to-babel.
         > 
         > - Similar to Recast, but twice faster, also simpler and easier in maintenance, since it supports only Babel.
         > - As opinionated as Prettier, but has more user-friendly output and works directly with AST.
         > - Like ESLint but works directly with Babel AST.
         > - Easily extendable with help of Overrides.
    - > What can be said about recast can probably also be said to a lesser degree about `ast-types`
- https://github.com/codemod-js/codemod
  - > codemod rewrites JavaScript and TypeScript using babel plugins
- https://github.com/unjs/magicast
  - > Programmatically modify JavaScript and TypeScript source codes with a simplified, elegant and familiar syntax powered by recast and babel.

### estools + related

- https://github.com/estools
  - https://github.com/estools/escope
    - > Escope: ECMAScript scope analyzer
    - https://github.com/mazurov/escope-demo
      - > Escope library: Scope Objects Visualization
      - https://mazurov.github.io/escope-demo/
      - https://github.com/lizhihao132/escope-demo/
        - > Scope Objects Visualization (By Esprima, Acorn, `escope`, `eslint-scope`)
        - Note: This is a fork of the original `escope-demo` repo that seems to add new features/etc
        - https://lizhihao132.github.io/escope-demo/
    - https://github.com/mazurov/eslevels
      - > ECMAScript scope levels analyzer based on escope library
      - > ECMAScript scope levels analyzer based on escope library. The original purpose of this library is to enable scope context coloring in javascript editors (for SublimeText in first order).
      - https://github.com/mazurov/eslevels-demo
        - > JavaScript scope coloring based on esprima toolbox
        - > This is a simple web application created to show features of eslevels javascript library — am ECMAScript scope levels analyzer based on escope library which original purpose was to enable scope context coloring in javascript editors (SublimeText in first order).
        - https://mazurov.github.io/eslevels-demo/
      - https://github.com/mazurov/sublime-levels
        - > SublimeText plugin for scope context coloring (ST2/ST3)
  - https://github.com/estools/esquery
    - > ECMAScript AST query library
    - > ESQuery is a library for querying the AST output by Esprima for patterns of syntax using a CSS style selector system
    - https://estools.github.io/esquery/
    - See also: https://eslint.org/docs/latest/extend/selectors
  - https://github.com/phenomnomnominal/tsquery
    - > TypeScript AST query library
    - > TSQuery is a port of the ESQuery API for TypeScript! TSQuery allows you to query a TypeScript AST for patterns of syntax using a CSS style selector system.
    - https://github.com/urish/tsquery-playground
      - > Playground for TSQuery
      - https://tsquery-playground.firebaseapp.com/
  - https://github.com/estools/esutils
    - > utility box for ECMAScript language tools
  - https://github.com/estools/estraverse
    - > Estraverse (`estraverse`) is ECMAScript traversal functions from `esmangle` project.
  - https://github.com/estools/esrecurse
    - > Esrecurse (`esrecurse`) is ECMAScript recursive traversing functionality.
  - https://github.com/estools/escodegen
    - > ECMAScript code generator
  - https://github.com/inikulin/esotope
    - > ECMAScript code generator on steroids
    - > This project has been started as a fork of escodegen with intention to speed up the original code. escodegen is a great project, however it was a constant bottleneck in our project, where we are doing a real-time JavaScript code instrumentation. When nearly 70% of the original code was rewritten, it became clear that it cannot be issued as a PR to the original repo and I decided to leave it as a standalone project. Currently esotope is x2 times faster than escodegen in node v0.10.x, and x4.5 times faster in node v0.11.x (benchmark). However in production we've seen x10 times performance gain in some cases.
  - https://github.com/estools/estemplate
    - > Proper (AST-based) JavaScript code templating with source maps support.
    - > This module allows to generate JavaScript AST from code template and AST nodes as substitutions.
      > This is more proper way of code templating since it works on AST not on code string, and thus preserves locations which allow to generate source maps in future.
  - https://github.com/estools/esshorten
    - > Shorten (mangle) names in JavaScript code
    - > `esshorten` provides name mangler, this shorten names in JavaScript code. mangler accepts JavaScript AST and generate modified AST with shortened names.
  - https://github.com/estools/esmangle
    - > `esmangle` is mangler / minifier for Mozilla Parser API AST
  - https://github.com/estools/espurify
    - > Clone AST without extra properties
    - > Leaves properties defined in The ESTree Spec (formerly known as Mozilla SpiderMonkey Parser API) only. Also note that extra informations (such as `loc`, `range` and `raw`) are eliminated too.
- https://github.com/ariya/esrefactor
  - > `esrefactor` (BSD licensed) is a little helper library for ECMAScript refactoring.

### Babel

- https://babeljs.io/
  - https://github.com/babel/website
    - > The Babel documentation website
  - https://babeljs.io/repl
    - https://github.com/babel/website/tree/main/js/repl
    - https://github.com/babel/sandboxes
      - > Babel repl-like codesandbox
    - Not sure any of these are the official ones.. but noting here anyway:
      - https://bvaughn.github.io/babel-repl/
        - https://github.com/bvaughn/babel-repl
          - > React powered Babel REPL
  - https://babeljs.io/docs/babel-parser
    - > @babel/parser
    - > The Babel parser (previously Babylon) is a JavaScript parser used in Babel
    - > Heavily based on `acorn` and `acorn-jsx`
    - https://babeljs.io/docs/babel-parser#api
    - https://babeljs.io/docs/babel-parser#output
      - > The Babel parser generates AST according to Babel AST format. It is based on ESTree spec with the following deviations...
        - https://github.com/babel/babel/blob/main/packages/babel-parser/ast/spec.md
      - > AST for JSX code is based on Facebook JSX AST
        - https://github.com/facebook/jsx/blob/main/AST.md
    - https://babeljs.io/docs/babel-parser#plugins
      - https://babeljs.io/docs/babel-parser#language-extensions
        - > Language extensions
      - https://babeljs.io/docs/babel-parser#ecmascript-proposals
        - > ECMAScript proposals
      - https://babeljs.io/docs/babel-parser#latest-ecmascript-features
        - > The following features are already enabled on the latest version of `@babel/parser`, and cannot be disabled because they are part of the language. You should enable these features only if you are using an older version.
    - https://github.com/babel/babel/blob/main/packages/babel-parser
      - https://github.com/babel/babel/blob/main/packages/babel-parser/src/util/scope.ts
        - > The functions in this module keep track of declared variables in the current scope in order to detect duplicate variable names.
        - ```js
          currentScope()
          inFunction()
          inStaticBlock()
          declareName(name: string, bindingType: BindingTypes, loc: Position)
          // etc
          ```
        - https://github.com/babel/babel/blob/main/packages/babel-parser/src/util/scope.ts#L24-L31
          - ```js
            var: Set<string> = new Set(); // A set of var-declared names in the current lexical scope
            lexical: Set<string> = new Set(); // A set of lexically-declared names in the current lexical scope
            functions: Set<string> = new Set(); // A set of lexically-declared FunctionDeclaration names in the current lexical scope`
            ```
  - https://babeljs.io/docs/babel-traverse
    - > @babel/traverse
    - > We can use it alongside the `babel` parser to traverse and update nodes
    - https://github.com/babel/babel/tree/main/packages/babel-traverse
      - https://github.com/babel/babel/blob/main/packages/babel-traverse/src/traverse-node.ts#L8-L20
        - > Traverse the children of given node
      - https://github.com/babel/babel/blob/main/packages/babel-traverse/src/scope/index.ts#L380-L394
        - ```typescript
          export default class Scope {
            uid;
            path: NodePath;
            block: t.Pattern | t.Scopable;
            labels;
            inited;
            bindings: { [name: string]: Binding };
            references: { [name: string]: true };
            globals: { [name: string]: t.Identifier | t.JSXIdentifier };
            uids: { [name: string]: boolean };
            data: { [key: string | symbol]: unknown };
            crawling: boolean;
          ```
        - ```javascript
          rename(oldName: string, newName?: string, /* Babel 7 - block?: t.Pattern | t.Scopable */)
          dump()
          getProgramParent() // Walk up to the top of the scope tree and get the `Program`.
          getFunctionParent() // Walk up the scope tree until we hit either a Function or return null.
          getBlockParent() // Walk up the scope tree until we hit either a BlockStatement/Loop/Program/Function/Switch or reach the very top and hit Program.
          getPatternParent() // Walk up from a pattern scope (function param initializer) until we hit a non-pattern scope, then returns its block parent
          getAllBindings(): Record<string, Binding> // Walks the scope tree and gathers **all** bindings.
          getAllBindingsOfKind(...kinds: string[]): Record<string, Binding> // Walks the scope tree and gathers all declarations of `kind`.
          getBinding(name: string): Binding | undefined
          getOwnBinding(name: string): Binding | undefined
          parentHasBinding(name: string, opts?: { noGlobals?: boolean; noUids?: boolean })
          // etc
          ```
      - https://github.com/babel/babel/blob/main/packages/babel-traverse/src/path/index.ts#L36-L51
        - `class NodePath<T extends t.Node = t.Node> {`
        - ```js
          declare parent: t.ParentMaps[T["type"]];
          declare hub: HubInterface;
          declare data: Record<string | symbol, unknown>;
          // TraversalContext is configured by setContext
          declare context: TraversalContext;
          declare scope: Scope;
          ```
        - ```js
          debug(message: string) // Generates a debug message with the context of the path location
          toString() // Generates the code for this path
          // etc
          ```
  - https://babeljs.io/docs/babel-generator
    - > @babel/generator
    - > Turns an AST into code.
  - https://babeljs.io/docs/babel-template
    - > @babel/template
    - > When calling template as a function with a string argument, you can provide placeholders which will get substituted when the template is used.
  - https://babeljs.io/docs/babel-code-frame
    - > @babel/code-frame
    - > Babel Code Frame is a package in the Babel toolchain that generates errors containing a "code frame" which points to specific source locations in the code, aiding in debugging and error analysis
  - https://babeljs.io/docs/babel-types
    - https://babeljs.io/docs/babel-types#aliases
      - https://babeljs.io/docs/babel-types#scopable
        - > A cover of `FunctionParent` and `BlockParent`.
        - https://babeljs.io/docs/babel-types#functionparent
          - > A cover of AST nodes that start an execution context with new `VariableEnvironment`. In other words, they define the scope of `var` declarations. `FunctionParent` did not include `Program` since Babel 7.
        - https://babeljs.io/docs/babel-types#blockparent
          - > A cover of AST nodes that start an execution context with new `LexicalEnvironment`. In other words, they define the scope of `let` and `const` declarations.
  - https://babeljs.io/docs/babel-helper-module-imports
    - > @babel/helper-module-imports
  - https://babeljs.io/docs/babel-helper-validator-identifier
    - > @babel/helper-validator-identifier is a utility package for parsing JavaScript keywords and identifiers. It provides several helper functions for identifying valid identifier names and detecting reserved words and keywords.
  - https://babeljs.io/docs/babel-helper-environment-visitor
    - > @babel/helper-environment-visitor is a utility package that provides a current this context visitor.
  
### `semantic` / `tree-sitter` + related

- https://github.com/github/semantic
  - > Parsing, analyzing, and comparing source code across many languages
- https://github.com/tree-sitter/tree-sitter
  - > An incremental parsing system for programming tools
  - https://github.com/tree-sitter/tree-sitter/blob/master/lib/binding_web/
    - > WebAssembly bindings to the Tree-sitter parsing library.
  - https://github.com/tree-sitter/tree-sitter/tree/master/cli
    - > The Tree-sitter CLI allows you to develop, test, and use Tree-sitter grammars from the command line.
  - https://tree-sitter.github.io/tree-sitter/
    - > Tree-sitter is a parser generator tool and an incremental parsing library. It can build a concrete syntax tree for a source file and efficiently update the syntax tree as the source file is edited.
    - https://tree-sitter.github.io/tree-sitter/playground
    - https://tree-sitter.github.io/tree-sitter/using-parsers
    - https://tree-sitter.github.io/tree-sitter/creating-parsers
    - https://tree-sitter.github.io/tree-sitter/syntax-highlighting
      - https://github.com/tree-sitter/tree-sitter/tree/master/highlight
    - https://tree-sitter.github.io/tree-sitter/code-navigation-systems
      - > Tree-sitter can be used in conjunction with its tree query language as a part of code navigation systems. An example of such a system can be seen in the tree-sitter tags command, which emits a textual dump of the interesting syntactic nodes in its file argument. A notable application of this is GitHub’s support for search-based code navigation. This document exists to describe how to integrate with such systems, and how to extend this functionality to any language with a Tree-sitter grammar.
      - https://tree-sitter.github.io/tree-sitter/code-navigation-systems#tagging-and-captures
        - > Tagging is the act of identifying the entities that can be named in a program. We use Tree-sitter queries to find those entities. Having found them, you use a syntax capture to label the entity and its name.
        - > The essence of a given tag lies in two pieces of data: the role of the entity that is matched (i.e. whether it is a definition or a reference) and the kind of that entity, which describes how the entity is used (i.e. whether it’s a class definition, function call, variable reference, and so on). Our convention is to use a syntax capture following the @role.kind capture name format, and another inner capture, always called @name, that pulls out the name of a given identifier.
        - > A more sophisticated query [can be found in the JavaScript Tree-sitter repository]([url](https://github.com/tree-sitter/tree-sitter-javascript/blob/fdeb68ac8d2bd5a78b943528bb68ceda3aade2eb/queries/tags.scm#L63-L70))
      - https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries
        - > Many code analysis tasks involve searching for patterns in syntax trees. Tree-sitter provides a small declarative language for expressing these patterns and searching for matches.
        - https://tree-sitter.github.io/tree-sitter/using-parsers#query-syntax
          - > A query consists of one or more patterns, where each pattern is an S-expression that matches a certain set of nodes in a syntax tree. The expression to match a given node consists of a pair of parentheses containing two things: the node’s type, and optionally, a series of other S-expressions that match the node’s children.
        - https://tree-sitter.github.io/tree-sitter/using-parsers#the-query-api
- https://github.com/tree-sitter/node-tree-sitter
  - > Node.js bindings for tree-sitter
- https://www.npmjs.com/package/web-tree-sitter
  - > WebAssembly bindings to the Tree-sitter parsing library.
  - https://github.com/tree-sitter/tree-sitter/tree/master/lib/binding_web
    - > WebAssembly bindings to the Tree-sitter parsing library
  - https://crates.io/crates/tree-sitter-javascript
    - https://github.com/tree-sitter/tree-sitter-javascript
    - > JavaScript and JSX grammar for [tree-sitter](https://github.com/tree-sitter/tree-sitter). For TypeScript, see [tree-sitter-typescript](https://github.com/tree-sitter/tree-sitter-typescript).
- https://github.com/afnanenayet/diffsitter
  - > A tree-sitter based AST difftool to get meaningful semantic diffs
  - > `diffsitter` is very much a work in progress and nowhere close to production ready (yet). Contributions are always welcome!
  - > `diffsitter` creates semantically meaningful diffs that ignore formatting differences like spacing. It does so by computing a diff on the AST (abstract syntax tree) of a file rather than computing the diff on the text contents of the file.
  - > `diffsitter` uses the parsers from the `tree-sitter` project to parse source code. As such, the languages supported by this tool are restricted to the languages supported by `tree-sitter`.
  - https://news.ycombinator.com/item?id=27875333

### Shift AST

- https://github.com/shapesecurity/shift-spec
  - > Shift AST Specification
  - https://shift-ast.org/
- https://github.com/shapesecurity/shift-parser-js
  - > ECMAScript parser that produces a Shift format AST
- https://github.com/shapesecurity/shift-codegen-js
  - > Code generator for Shift format ASTs
- https://github.com/shapesecurity/shift-scope-js
  - Scope analyser for the Shift AST
- https://github.com/shapesecurity/shift-reducer-js
  - > Reducer for the Shift AST format
- https://github.com/shapesecurity/shift-fuzzer-js
  - > Generate random valid Shift format ASTs
- https://github.com/codemodsquad/astx
  - > Super powerful structural search and replace for JavaScript and TypeScript to automate your refactoring

### `swc`

- https://swc.rs/
  - > SWC is an extensible Rust-based platform for the next generation of fast developer tools. It's used by tools like Next.js, Parcel, and Deno, as well as companies like Vercel, ByteDance, Tencent, Shopify, and more.
    > 
    > SWC can be used for both compilation and bundling. For compilation, it takes JavaScript / TypeScript files using modern JavaScript features and outputs valid code that is supported by all major browsers.
    > 
    > SWC is 20x faster than Babel on a single thread and 70x faster on four cores.
  - https://swc.rs/playground
    - This can show both transformed code, as well as the AST
    - https://github.com/swc-project/swc-playground
      - > The SWC playground
      - > Two editors powered by Monaco Editor for editing input code and showing output code.
  - https://swc-css.netlify.app/
    - https://github.com/g-plane/swc-css-playground
      - > Playground for SWC CSS
      - > Currently there's only AST viewer
  - https://swc.rs/docs/usage/core
    - > @swc/core
    - > These are the core SWC APIs mainly useful for build tool authors
    - https://swc.rs/docs/usage/core#parse
      - > parse Returns `Promise<Script | Module>`
  - https://swc.rs/docs/usage/wasm
    - > `@swc/wasm-web`
      > This modules allows you to synchronously transform code inside the browser using WebAssembly.
    - https://codesandbox.io/examples/package/@swc/wasm-web
      - > Use this online `@swc/wasm-web` playground to view and fork `@swc/wasm-web` example apps and templates on CodeSandbox
    - Some example usages of `@swc/wasm-web`
      - https://github.com/fkling/astexplorer/blob/master/website/src/parsers/js/swc.js#L3
      - https://github.com/sxzz/ast-explorer/blob/main/composables/language/javascript.ts#L74-L109
    - https://github.com/swc-project/swc/discussions/3713
      - > Running a plugin with `@swc/wasm-web`
- https://github.com/swc-project/swc
  - > Rust-based platform for the Web
  - > SWC (stands for Speedy Web Compiler) is a super-fast TypeScript / JavaScript compiler written in Rust. It's a library for Rust and JavaScript at the same time. If you are using SWC from Rust, see rustdoc and for most users, your entry point for using the library will be parser.
    - https://rustdoc.swc.rs/swc/
      - > The main crate of the swc project
    - https://rustdoc.swc.rs/swc_ecma_parser/
      - > EcmaScript/TypeScript parser for the rust programming language.
      - https://rustdoc.swc.rs/swc_ecmascript/
      - https://rustdoc.swc.rs/swc_ecma_ast/
      - https://rustdoc.swc.rs/swc_ecma_visit/
      - https://rustdoc.swc.rs/swc_ecma_codegen/
      - https://rustdoc.swc.rs/swc_ecma_dep_graph/
      - https://rustdoc.swc.rs/swc_ecma_minifier/
        - > JavaScript minifier implemented in rust
      - https://rustdoc.swc.rs/swc_ecma_transforms/
      - etc
    - https://rustdoc.swc.rs/swc_estree_compat/
      - https://rustdoc.swc.rs/swc_estree_ast/
        - https://rustdoc.swc.rs/swc_estree_compat/babelify/trait.Babelify.html
        - https://rustdoc.swc.rs/swc_estree_compat/swcify/trait.Swcify.html
          - > Used to convert a babel ast node to
    - https://rustdoc.swc.rs/swc_html_parser/
      - https://rustdoc.swc.rs/swc_html_ast/
    - https://rustdoc.swc.rs/swc_css_parser/
      - https://rustdoc.swc.rs/swc_css_ast/
    - https://rustdoc.swc.rs/swc_xml_parser/
      - https://rustdoc.swc.rs/swc_xml_ast/
        - > AST definitions for XML
    - https://rustdoc.swc.rs/wasmparser/
      - > A simple event-driven library for parsing WebAssembly binary files (or streams).
        > The parser library reports events as they happen and only stores parsing information for a brief period of time, making it very fast and memory-efficient. The event-driven model, however, has some drawbacks. If you need random access to the entire WebAssembly data-structure, this is not the right library for you. You could however, build such a data-structure using this library.
       - https://rustdoc.swc.rs/wast/
         - > A crate for low-level parsing of the WebAssembly text formats: WAT and WAST.
           > This crate is intended to be a low-level detail of the wat crate, providing a low-level parsing API for parsing WebAssembly text format structures. The API provided by this crate is very similar to syn and provides the ability to write customized parsers which may be an extension to the core WebAssembly text format. For more documentation see the parser module.
           - https://rustdoc.swc.rs/wast/parser/
             - > Traits for parsing the WebAssembly Text format
               > This module contains the traits, abstractions, and utilities needed to define custom parsers for WebAssembly text format items.
             - > The top-level parse function can be used to fully parse AST fragments
- https://www.christopherbiscardi.com/how-to-print-a-javascript-ast-using-swc-and-rust
  - > How to print a JavaScript AST using SWC and Rust
- https://blog.logrocket.com/writing-webpack-plugins-rust-using-swc/
  - > Writing webpack plugins in Rust using SWC for faster builds
  - > In this tutorial, we’ll create a simple custom Rust-based SWC plugin and compile it to Wasm, so it can be used in a webpack build using swc-loader. We’ll build our simple plugin and import it in a JavaScript project using webpack, configure it as a plugin running with the swc-loader within webpack, and then check that the plugin was run and that it worked.
- https://chat.openai.com/c/1ab6cfcd-3fd5-43d8-b13e-a604239450ca
  - ChatGPT chat showing example of creating rust parsing code (using `swc_ecma_parser`, `JsValue::from_serde`, etc), compiling to webassembly with `wasm-pack`, and using it from JavaScript
  - https://github.com/rustwasm/wasm-pack
    - > This tool seeks to be a one-stop shop for building and working with rust- generated WebAssembly that you would like to interop with JavaScript, in the browser or with Node.js. `wasm-pack` helps you build rust-generated WebAssembly packages that you could publish to the npm registry, or otherwise use alongside any javascript packages in workflows that you already use
    - https://rustwasm.github.io/wasm-pack/book/
- https://github.com/coderaiser/swc-to-babel
  - > convert SWC to Babel AST
  - https://github.com/coderaiser/estree-to-babel
    - > convert estree ast to babel
    - > Convert ESTree-compatible JavaScript AST to Babel AST.
    - https://github.com/j4k0xb/estree-to-babel/tree/perf
      - https://github.com/coderaiser/estree-to-babel/compare/master...j4k0xb:estree-to-babel:perf
        - Replaces cherow with meriyah
        - > When using [`meriyah`](https://github.com/meriyah/meriyah) and `estree-to-babel`, its up to 2.8x faster than [`@babel/parser`](https://babeljs.io/docs/babel-parser) alone.
          - https://github.com/meriyah/meriyah
            - > 100% compliant, self-hosted javascript parser with high focus on both performance and stability. Stable and already used in production.
            - https://meriyah.github.io/meriyah/ (Playground)

### `esbuild`

- https://github.com/evanw/esbuild
  - > An extremely fast bundler for the web
  - Written in Golang
  - https://esbuild.github.io/
    - https://esbuild.github.io/faq/#upcoming-roadmap
      - > I am not planning to include these features in esbuild's core itself:
        > - ..snip..
        > - An API for custom AST manipulation 
        > - ..snip..
        > 
        > I hope that the extensibility points I'm adding to esbuild (plugins and the API) will make esbuild useful to include as part of more customized build workflows, but I'm not intending or expecting these extensibility points to cover all use cases.
        - https://esbuild.github.io/plugins/
        - https://esbuild.github.io/api/
        - https://news.ycombinator.com/item?id=29004200
          - > ESBuild does not support any AST transforms directly
            > 
            > You can add it, via plugins, but its a serious limitation for a project like Next.js which require's these types of transforms
            > 
            > You also end up with diminishing returns with the more plugins in you add to esbuild, and I imagine its worse with js plugins than it is with go based ones, none the less, you have zero access to it directly
          - > It is trivial to write extensions for esbuild. We've written extensive plugins to perform ast transformations that all run, collectively, in under 0.5 seconds.
            > Make a plugin, add acorn and escodegen.
            - This implies that the plugins are doing the AST transformation outside of esbuild itself (likely still running in JS), so wouldn't really benefit from the fact that esbuild is written in golang like I was hoping.
        - https://github.com/evanw/esbuild/issues/2172
          - > Forking esbuild to build an AST plugin tool
          - > The internal AST is not designed for this use case at all, and it’s not a use case that I’m going to spend time supporting (so I’m not going to spend time documenting exactly how to do it). I recommend using some other tool if you want to do AST-level stuff, especially because keeping a hack like this working over time as esbuild changes might be a big pain for you.
          - > 
          - > If it really want to do this with esbuild, know that the AST is not cleanly abstracted and is only intended for use with esbuild (e.g. uses a lot of internal data structures, has implicit invariants regarding symbols and tree shaking, does some weird things for performance reasons).

### Source Maps

- https://github.com/mozilla/source-map
  - > Consume and generate source maps
  - > This is a library to generate and consume the source map format [described here](https://docs.google.com/document/d/1U1RGAehQwRypUTovF1KRlpiOFze0b-_2gc6fAH0KY0k/edit#heading=h.1ce2c87bpj24)
  - https://github.com/mozilla/source-map#examples
  - https://github.com/mozilla/source-map#api
- https://github.com/parcel-bundler/source-map
  - > A fast source map manipulation, generation and consumption library written in Rust and Node.js
  - https://github.com/parcel-bundler/source-map#why-did-we-write-this-library
    - > Why did we write this library
      > Parcel is a performance conscious bundler, and therefore we like to optimise Parcel's performance as much as possible.
      > 
      > Our original source-map implementation used mozilla's source-map and a bunch of javascript and had issues with memory usage and serialization times (we were keeping all mappings in memory using JS objects and write/read it using JSON for caching).
      > 
      > This implementation has been written from scratch in Rust minimizing the memory usage, by utilizing indexes for sources and names and optimizing serialization times by using Buffers instead of JSON for caching.
- https://github.com/denandz/sourcemapper
  - > Extract JavaScript source trees from Sourcemap files
  - > Sourcemapper is a bit of golang to parse a sourcemap, as generated by webpack or similar, and spit out the original JavaScript files, recreating the source tree based on the file paths in the sourcemap.
  - https://pulsesecurity.co.nz/articles/javascript-from-sourcemaps
    - > Extracting JavaScript from SourceMaps
- https://github.com/paazmaya/shuji
  - > Reverse engineering JavaScript and CSS sources from sourcemaps
- https://github.com/Anthonyzou/Sourcemap-Unpack
  - > Unpack source maps
- https://github.com/lydell/source-map-visualize
  - > Quickly open an online source map visualization with local files
- https://github.com/sokra/source-map-visualization
  - > Just a simple hacky visualisation of SourceMaps
  - https://sokra.github.io/source-map-visualization/#typescript

### Visualisation/etc

- https://github.com/keeyipchan/esgoggles
  - > Browser IDE for reading and exploring javascript code
    - > Demo 1 -- style 1: https://keeyipchan.github.io/esgoggles/demo/style1.html (use Chrome)
    - > Demo 2 -- style 2 with variable scopes: https://keeyipchan.github.io/esgoggles/demo/style2.html (use Chrome)
- https://github.com/Bogdan-Lyashenko/js-code-to-svg-flowchart
  - > `js2flowchart` - a visualization library to convert any JavaScript code into beautiful SVG flowchart. Learn other’s code. Design your code. Refactor code. Document code. Explain code.
  - > Imagine a library which takes any JS code and generate SVG flowchart from it, works on client and server. Allows you easily adjust styles scheme for your context or demonstrate your code logic from different abstractions levels. Highlighting, destructing whole blocks, custom modifiers for your needs etc.
  - https://bogdan-lyashenko.github.io/js-code-to-svg-flowchart/docs/live-editor/

## Browser Based Code Editors / IDEs

In addition to the links directly below, also make sure to check out the various online REPL/playground tools linked under various other parts of this page too (eg. babel, swc, etc):

- https://github.com/microsoft/TypeScript-Website/tree/v2/packages/playground
  - > This is the JS tooling which powers the https://www.typescriptlang.org/play/
  - > It is more or less vanilla DOM-oriented JavaScript with as few dependencies as possible. Originally based on the work by Artem Tyurin but now it's diverged far from that fork.
    - https://github.com/agentcooper/typescript-play
  - https://github.com/microsoft/TypeScript-Website/tree/v2/packages/sandbox
    - > The TypeScript Sandbox is the editor part of the TypeScript Playground. It's effectively an opinionated fork of `monaco-typescript` with extra extension points so that projects like the TypeScript Playground can exist.
  - https://github.com/microsoft/TypeScript-Playground-Samples
    - > Examples of TypeScript Playground Plugins for you to work from
    - > This is a series of example plugins, which are extremely well documented and aim to give you samples to build from depending on what you want to build.
    - > - TS Compiler API: Uses `@typescript/vfs` to set up a TypeScript project in the browser, and then displays all of the top-level functions as AST nodes in the sidebar.
      > - TS Transformers Demo: Uses a custom TypeScript transformer when emitting JavaScript from the current file in the Playground.
      > - Using a Web-ish npm Dependency: Uses a dependency which isn't entirely optimised for running in a web page, but doesn't have too big of a dependency tree that it this becomes an issue either
      > - Presenting Information Inline: Using a fraction of the extensive Monaco API (monaco is the text editor at the core of the Playground) to showcase what parts of a TypeScript file would be removed by a transpiler to make it a JS file.

### CodeMirror

- https://codemirror.net/
  - > CodeMirror is a code editor component for the web. It can be used in websites to implement a text input field with support for many editing features, and has a rich programming interface to allow further extension.
  - > CodeMirror is open source under a permissive license (MIT).
  - > A full parser package, often with language-specific integration and extension code, exists for the following languages
    - https://github.com/codemirror/lang-javascript
      - > JavaScript language support for the CodeMirror code editor
    - etc
  - > There is also a collection of CodeMirror 5 modes that can be used, and a list of community-maintained language packages. If your language is not listed above, you may still find a solution there.
    - https://github.com/codemirror/legacy-modes
      - > Collection of ported legacy language modes for the CodeMirror code editor
    - https://codemirror.net/docs/community/#language
  - https://codemirror.net/docs/community/
    - > Community Packages
    - > This page lists CodeMirror-related packages maintained by the wider community.
- https://github.com/codemirror/dev
  - > Development repository for the CodeMirror editor project
  - > This is the central repository for CodeMirror. It holds the bug tracker and development scripts.
    >
    > If you want to use CodeMirror, install the separate packages from npm, and ignore the contents of this repository. If you want to develop on CodeMirror, this repository provides scripts to install and work with the various packages.
- https://github.com/uiwjs/react-codemirror
  - > CodeMirror 6 component for React
  - https://uiwjs.github.io/react-codemirror/

### `monaco-editor`

- https://microsoft.github.io/monaco-editor/
  - > The Monaco Editor is the code editor that powers VS Code.
  - > It is licensed under the MIT License and supports Edge, Chrome, Firefox, Safari and Opera. The Monaco editor is not supported in mobile browsers or mobile web frameworks.
  - https://microsoft.github.io/monaco-editor/docs.html
  - https://microsoft.github.io/monaco-editor/playground.html
  - https://microsoft.github.io/monaco-editor/monarch.html
    - > This document describes how to create a syntax highlighter using the Monarch library. This library allows you to specify an efficient syntax highlighter, using a declarative lexical specification (written as a JSON value). The specification is expressive enough to specify sophisticated highlighters with complex state transitions, dynamic brace matching, auto-completion, other language embeddings, etc. as shown in the 'advanced' topic sections of this document.
  - See also: https://code.visualstudio.com/docs/editor/vscode-web
- https://github.com/microsoft/monaco-editor
  - > A browser based code editor
    - > The Monaco Editor is the fully featured code editor from VS Code. Check out the VS Code docs to see some of the supported features.
      - https://code.visualstudio.com/docs/editor/editingevolved
        - https://code.visualstudio.com/docs/editor/editingevolved#_go-to-definition
          - > Go to Definition
          - > If a language supports it, you can go to the definition of a symbol by pressing F12.
        - https://code.visualstudio.com/docs/editor/editingevolved#_go-to-type-definition
          - > Go to Type Definition
          - > Some languages also support jumping to the type definition of a symbol by running the Go to Type Definition command from either the editor context menu or the Command Palette. This will take you to the definition of the type of a symbol.
        - https://code.visualstudio.com/docs/editor/editingevolved#_go-to-implementation
          - > Go to Implementation
          - > Languages can also support jumping to the implementation of a symbol by pressing ⌘F12. For an interface, this shows all the implementors of that interface and for abstract methods, this shows all concrete implementations of that method.
        - https://code.visualstudio.com/docs/editor/editingevolved#_go-to-symbol
          - > Go to Symbol
          - > You can navigate symbols inside a file with ⇧⌘O. By typing : the symbols will be grouped by category. Press Up or Down and navigate to the place you want.
        - https://code.visualstudio.com/docs/editor/editingevolved#_open-symbol-by-name
          - > Open symbol by name
          - > Some languages support jumping to a symbol across files with ⌘T. Type the first letter of a type you want to navigate to, regardless of which file contains it, and press Enter.
        - https://code.visualstudio.com/docs/editor/editingevolved#_peek
          - > Peek
          - > We think there's nothing worse than a big context switch when all you want is to quickly check something. That's why we support peeked editors. When you execute a Go to References search (via ⇧F12), or a Peek Definition (via ⌥F12), we embed the result inline
        - https://code.visualstudio.com/docs/editor/editingevolved#_bracket-matching
          - > Bracket matching
          - > Matching brackets will be highlighted as soon as the cursor is near one of them.
        - https://code.visualstudio.com/docs/editor/editingevolved#_reference-information
          - > Reference information
          - > Some languages like C# support inline reference information, that is updated live. This allows you to quickly analyze the impact of your edit or the popularity of your specific method or property throughout your project:
        - https://code.visualstudio.com/docs/editor/editingevolved#_rename-symbol
          - > Rename symbol
          - > Some languages support rename symbol across files. Press F2 and then type the new desired name and press Enter. All usages of the symbol will be renamed, across files.
        - https://code.visualstudio.com/docs/editor/editingevolved#_inlay-hints
          - > Inlay Hints
          - > Some languages provide inlay hints: that is additional information about source code that is rendered inline. This is usually used to show infered types.
        - etc

## Obfuscation / Deobfuscation

- https://github.com/terser/terser
  - > JavaScript parser, mangler and compressor toolkit for ES6+
  - https://terser.org/
  - https://try.terser.org/ (REPL, Playground)
  - https://terser.org/docs/options/#compress-options
    - > Compress options
    - `keep_classnames`, `keep_fnames`, `module`, `toplevel`, etc
  - https://terser.org/docs/options/#mangle-options
    - > Mangle options
    - `keep_classnames`, `keep_fnames`, `module`, `toplevel`, etc
  - https://terser.org/docs/api-reference/
    - > `mangle` (default `true`) — pass `false` to skip mangling names, or pass an object to specify mangle options
    - > `module` (default `false`) — Use when minifying an ES6 module. `"use strict"` is implied and names can be mangled on the top scope. If `compress` or `mangle` is enabled then the `toplevel` option will be enabled.
    - > `nameCache` (default `null`) - pass an empty object `{}` or a previously used `nameCache` object if you wish to cache mangled variable and property names across multiple invocations of `minify()`. Note: this is a read/write property. `minify()` will read the name cache state of this object and update it during minification so that it may be reused or externally persisted by the user.
    - > `keep_classnames` (default: `undefined`) - pass `true` to prevent discarding or mangling of class names. Pass a regular expression to only keep class names matching that regex.
    - > `keep_fnames` (default: false) - pass `true` to prevent discarding or mangling of function names. Pass a regular expression to only keep function names matching that regex. Useful for code relying on `Function.prototype.name`. If the top level `minify` option `keep_classnames` is undefined it will be overridden with the value of the top level `minify` option `keep_fnames`.
  - https://github.com/terser/terser/blob/main/lib/minify.js#L176-L200
    - ```js
      var toplevel;
      if (files instanceof AST_Toplevel) {
          toplevel = files;
      } else {
          if (typeof files == "string") {
              files = [ files ];
          }
      ```
    - ```js
      // disable rename on harmony due to expand_names bug in for-of loops
      // https://github.com/mishoo/UglifyJS2/issues/2794
      if (0 && options.rename) {
        toplevel.figure_out_scope(options.mangle);
        toplevel.expand_names(options.mangle);
      }
      ```
      - https://github.com/terser/terser/blob/master/lib/scope.js#L203-L479
        - `AST_Scope.DEFMETHOD("figure_out_scope", function(options, { parent_scope = null, toplevel = this } = {}) {`
      - https://github.com/terser/terser/blob/master/lib/scope.js#L930-L966
        - `AST_Toplevel.DEFMETHOD("expand_names", function(options) {`
      - https://github.com/terser/terser/blob/master/lib/scope.js#L907-L928
        - `AST_Toplevel.DEFMETHOD("find_colliding_names", function(options) {`
    - ```js
      if (options.compress) {
        toplevel = new Compressor(options.compress, {
          mangle_options: options.mangle
        }).compress(toplevel);
      }
      ```
      - https://github.com/terser/terser/blob/master/lib/compress/index.js#L213
        - `class Compressor extends TreeWalker {`
      - TODO: add reference to compress function here
    - ```js
      if (options.mangle) toplevel.figure_out_scope(options.mangle);`
      ```
      - https://github.com/terser/terser/blob/master/lib/scope.js#L203-L479
        - `AST_Scope.DEFMETHOD("figure_out_scope", function(options, { parent_scope = null, toplevel = this } = {}) {`
    - ```js
      if (options.mangle) {
        base54.reset();
        toplevel.compute_char_frequency(options.mangle);
        toplevel.mangle_names(options.mangle);
      }
      ```
      - https://github.com/terser/terser/blob/master/lib/scope.js#L1015-L1061
        - `base54`
      - https://github.com/terser/terser/blob/master/lib/scope.js#L973-L1013
        - `AST_Toplevel.DEFMETHOD("compute_char_frequency", function(options) {`
      - https://github.com/terser/terser/blob/master/lib/scope.js#L806-L905
        - `AST_Toplevel.DEFMETHOD("mangle_names", function(options) {`
    - ```js
      if (options.mangle && options.mangle.properties) {
        toplevel = mangle_properties(toplevel, options.mangle.properties);
      }
      ```
      - https://github.com/terser/terser/blob/master/lib/propmangle.js#L152
        - `function mangle_private_properties(ast, options) {`
      - https://github.com/terser/terser/blob/master/lib/propmangle.js#L216-L425
        - `function mangle_properties(ast, options, annotated_props = find_annotated_props(ast)) {`
        - ```js
          options = defaults(options, {
            // ..snip..
            nth_identifier: base54,
            // ..snip..
          }, true);
          ```
        - `var nth_identifier = options.nth_identifier;`
        - https://github.com/terser/terser/blob/master/lib/propmangle.js#L381-L407
          - `function mangle(name) {`
          - ```js
            // debug mode: use a prefix and suffix to preserve readability, e.g. o.foo -> o._$foo$NNN_.
            var debug_mangled = "_$" + name + "$" + debug_name_suffix + "_";
            ```
          - ```js
            if (!mangled) {
                do {
                    mangled = nth_identifier.get(++cname);
                } while (!can_mangle(mangled));
            }

            cache.set(name, mangled);
            ```
        - https://github.com/terser/terser/blob/master/lib/propmangle.js#L409-L424
          - `function mangleStrings(node) {`
- https://github.com/javascript-obfuscator/javascript-obfuscator
  - > A powerful obfuscator for JavaScript and Node.js
  - https://obfuscator.io/
- https://github.com/MichaelXF/js-confuser
  - > JS-Confuser is a JavaScript obfuscation tool to make your programs *impossible* to read.
  - https://js-confuser.com/
  - https://github.com/MichaelXF/js-confuser/blob/master/docs/Integrity.md
    - > JSConfuser can detect changes to the source and prevent execution.
      > If the code is determined modified, the tampered code will not run.
    > JavaScript has a sneaky method to view the source code any function. Calling `.toString()` on any function reveals the raw source code. Integrity hashes the code during obfuscation phase and embeds an IF-statement within the code. We used an additional regex to remove spaces, newlines, braces, and commas to ensure the hash isn't too sensitive.
- https://github.com/ben-sb/javascript-deobfuscator
  - > General purpose JavaScript deobfuscator
  - https://deobfuscate.io/
- https://github.com/ben-sb/obfuscator-io-deobfuscator
  - > A deobfuscator for scripts obfuscated by Obfuscator.io
  - https://obf-io.deobfuscate.io/
- https://github.com/relative/synchrony
  - > javascript cleaner & deobfuscator (primarily javascript-obfuscator/obfuscator.io)
  - https://deobfuscate.relative.im/

### Variable Name Mangling

- https://hex-rays.com/blog/igors-tip-of-the-week-34-dummy-names/
  - > In IDA’s disassembly, you may have often observed names that may look strange and cryptic on first sight: `sub_73906D75`, `loc_40721B`, `off_40A27C` and more. In IDA’s terminology, they’re called dummy names. They are used when a name is required by the assembly syntax but there is nothing suitable available
  - https://www.hex-rays.com/products/ida/support/idadoc/609.shtml
    - > IDA Help: Names Representation
    - > Dummy names are automatically generated by IDA. They are used to denote subroutines, program locations and data. Dummy names have various prefixes depending on the item type and value
- https://binary.ninja/2023/09/15/3.5-expanded-universe.html#automatic-variable-naming
  - > Automatic Variable Naming
    > One easy way to improve decompilation output is to come up with [better default names](https://github.com/Vector35/binaryninja-api/issues/2558) for variables. There’s a lot of possible defaults you could choose and a number of different strategies are seen throughout different reverse engineering tools. Prior to 3.5, Binary Ninja left variables named based on their origin. Stack variables were var_OFFSET, register-based variables were reg_COUNTER, and global data variables were (data_). While this scheme isn’t changing, we’re being much more intelligent about situations where additional information is available.
    > 
    > For example, if a variable is passed to a function and a variable name is available, we can now make a much better guess for the variable name. This is most obvious in binaries with type libraries.
  - > This isn’t the only style of default names. Binary Ninja also will name loop counters with simpler names like `i`, or `j`, `k`, etc (in the case of nested loops)
- Webpack
  - https://webpack.js.org/configuration/optimization/#optimizationchunkids
    - > `optimization.chunkIds`
    - > Tells webpack which algorithm to use when choosing chunk ids.
    - > - `'natural'`: Numeric ids in order of usage.
      > - `'named'`: Readable ids for better debugging.
      > - `'deterministic'`: Short numeric ids which will not be changing between compilation. Good for long term caching. Enabled by default for `production` mode.
      > - `'size'`: Numeric ids focused on minimal initial download size.
      > - `'total-size'`: numeric ids focused on minimal total download size.
  - https://webpack.js.org/configuration/optimization/#optimizationmangleexports
    - > `optimization.mangleExports` allows to control export mangling.
      > By default `optimization.mangleExports`: `'deterministic'` is enabled in `production` mode and disabled elsewise.
    - > - `'size'`: Short names - usually a single char - focused on minimal download size.
      > - `'deterministic'`: Short names - usually two chars - which will not change when adding or removing exports. Good for long term caching.
      > - `true`: Same as `'deterministic'`
      > - `false`: Keep original name. Good for readability and debugging.
  - https://webpack.js.org/configuration/optimization/#optimizationmanglewasmimports
    - `optimization.mangleWasmImports`
      - > When set to true tells webpack to reduce the size of WASM by changing imports to shorter strings. It mangles module and export names.
  - https://webpack.js.org/configuration/optimization/#optimizationminimize
    - `optimization.minimize`
      - > Tell webpack to minimize the bundle using the `TerserPlugin` or the plugin(s) specified in `optimization.minimizer`
        - https://webpack.js.org/plugins/terser-webpack-plugin/
          - > TerserWebpackPlugin
          - > This plugin uses terser to minify/minimize your JavaScript.
          - https://webpack.js.org/plugins/terser-webpack-plugin/#terseroptions
            - `keep_classnames`, `keep_fnames`, `mangle`, `nameCache`, etc
          - https://github.com/terser/terser
  - https://webpack.js.org/configuration/optimization/#optimizationminimizer
    - > `optimization.minimizer`
    - > Allows you to override the default minimizer by providing a different one or more customized `TerserPlugin` instances.
  - https://webpack.js.org/configuration/optimization/#optimizationmoduleids
    - > `optimization.moduleIds`
    - > Tells webpack which algorithm to use when choosing module ids. Setting `optimization.moduleIds` to false tells webpack that none of built-in algorithms should be used, as custom one can be provided via plugin.
    - > - `natural`: Numeric ids in order of usage.
      > - `named`: Readable ids for better debugging.
      > - `deterministic`: Module names are hashed into small numeric values.
      > - `size`: Numeric ids focused on minimal initial download size.
    - `deterministic` option is useful for long term caching, but still results in smaller bundles compared to `hashed`. Length of the numeric value is chosen to fill a maximum of 80% of the id space. By default a minimum length of 3 digits is used when `optimization.moduleIds` is set to `deterministic`. To override the default behaviour set `optimization.moduleIds` to `false` and use the `webpack.ids.DeterministicModuleIdsPlugin`
- https://github.com/estools/esshorten
  - > Shorten (mangle) names in JavaScript code
  - https://github.com/estools/esshorten/blob/master/lib/esshorten.js#L88-L138
    - `NameGenerator`, `mangle`, `mangleLabels`
  - https://github.com/estools/esshorten/blob/master/lib/utility.js#L64-L92
    - `generateNextName`

## Stack Graphs / Scope Graphs

- See also:
  - https://github.com/0xdevalias/chatgpt-source-watch/issues/11
    - > Explore stack graphs / scope graphs
- https://github.blog/changelog/2024-03-14-precise-code-navigation-for-typescript-projects/
  - > Precise code navigation is now available for all TypeScript repositories.
    > Precise code navigation gives more accurate results by only considering the set of classes, functions, and imported definitions that are visible at a given point in your code.
    > 
    > Precise code navigation is powered by the stack graphs framework.
    > You can read about how [we use stack graphs for code navigation](https://github.blog/2021-12-09-introducing-stack-graphs/) and visit the [stack graphs definition for TypeScript](https://github.com/github/stack-graphs/tree/main/languages/tree-sitter-stack-graphs-typescript) to learn more.
    - https://github.blog/2021-12-09-introducing-stack-graphs/
      - > Introducing stack graphs
      - > Precise code navigation is powered by stack graphs, a new open source framework we’ve created that lets you define the name binding rules for a programming language using a declarative, domain-specific language (DSL). With stack graphs, we can generate code navigation data for a repository without requiring any configuration from the repository owner, and without tapping into a build process or other CI job.
      - LOTS of interesting stuff in this post..
      - > As part of developing stack graphs, we’ve added a new graph construction language to Tree-sitter, which lets you construct arbitrary graph structures (including but not limited to stack graphs) from parsed CSTs. You use stanzas to define the gadget of graph nodes and edges that should be created for each occurrence of a Tree-sitter query, and how the newly created nodes and edges should connect to graph content that you’ve already created elsewhere.
        - https://github.com/tree-sitter/tree-sitter-graph
          - > `tree-sitter-graph`
            > The tree-sitter-graph library defines a DSL for constructing arbitrary graph structures from source code that has been parsed using tree-sitter.
          - https://marketplace.visualstudio.com/items?itemName=tree-sitter.tree-sitter-graph
            - > `tree-sitter-graph` support for VS Code
              > This language extension for VS Code provides syntax support for `tree-sitter-graph` files.
      - > Why aren’t we using the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) (LSP) or [Language Server Index Format](https://code.visualstudio.com/blogs/2019/02/19/lsif) (LSIF)?
        >
        > To dig even deeper and learn more, I encourage you to check out my Strange Loop talk and the `stack-graphs` crate: our open source Rust implementation of these ideas.
        - https://github.com/github/stack-graphs
          - > Stack graphs
            > The crates in this repository provide a Rust implementation of stack graphs, which allow you to define the name resolution rules for an arbitrary programming language in a way that is efficient, incremental, and does not need to tap into existing build or program analysis tools.
          - https://docs.rs/stack-graphs/latest/stack_graphs/
          - https://github.com/github/stack-graphs/tree/main/languages
            - > This directory contains stack graphs definitions for specific languages.
            - https://github.com/github/stack-graphs/tree/main/languages/tree-sitter-stack-graphs-javascript
              - > `tree-sitter-stack-graphs` definition for JavaScript
                > This project defines `tree-sitter-stack-graphs` rules for JavaScript using the `tree-sitter-javascript` grammar.
              - > The command-line program for `tree-sitter-stack-graphs-javascript` lets you do stack graph based analysis and lookup from the command line.
                - `cargo install --features cli tree-sitter-stack-graphs-javascript`
                - `tree-sitter-stack-graphs-javascript index SOURCE_DIR`
                - `tree-sitter-stack-graphs-javascript status SOURCE_DIR`
                - `tree-sitter-stack-graphs-javascript query definition SOURCE_PATH:LINE:COLUMN`
            - https://github.com/github/stack-graphs/tree/main/languages/tree-sitter-stack-graphs-typescript
              - > `tree-sitter-stack-graphs` definition for TypeScript
                > This project defines `tree-sitter-stack-graphs` rules for TypeScript using the `tree-sitter-typescript` grammar.
              - > The command-line program for `tree-sitter-stack-graphs-typescript` lets you do stack graph based analysis and lookup from the command line.
        - https://dcreager.net/talks/2021-strange-loop/
          - Redirects to https://dcreager.net/talks/stack-graphs/
          - > Incremental, zero-config Code Navigation using stack graphs.
          - > In this talk I’ll describe stack graphs, which use a graphical notation to define the name binding rules for a programming language. They work equally well for dynamic languages like Python and JavaScript, and for static languages like Go and Java. Our solution is fast — processing most commits within seconds of us receiving your push. It does not require setting up a CI job, or tapping into a project-specific build process. And it is open-source, building on the tree-sitter project’s existing ecosystem of language tools.
          - https://www.youtube.com/watch?v=l2R1PTGcwrE
            - > "Incremental, zero-config Code Nav using stack graphs" by Douglas Creager
          - https://media.dcreager.net/dcreager-strange-loop-2021-slides.pdf
          - https://media.dcreager.net/dcreager-2022-ucsc-lsd-slides.pdf
- https://docs.github.com/en/repositories/working-with-files/using-files/navigating-code-on-github
  - > GitHub has developed two code navigation approaches based on the open source [tree-sitter](https://github.com/tree-sitter/tree-sitter) and [stack-graphs](https://github.com/github/stack-graphs) library:
    > - Search-based - searches all definitions and references across a repository to find entities with a given name
    > - Precise - resolves definitions and references based on the set of classes, functions, and imported definitions at a given point in your code
    >
    > To learn more about these approaches, see "[Precise and search-based navigation](https://docs.github.com/en/repositories/working-with-files/using-files/navigating-code-on-github#precise-and-search-based-navigation)."
    - https://docs.github.com/en/repositories/working-with-files/using-files/navigating-code-on-github#precise-and-search-based-navigation
      - > Precise and search-based navigation
        > Certain languages supported by GitHub have access to precise code navigation, which uses an algorithm (based on the open source stack-graphs library) that resolves definitions and references based on the set of classes, functions, and imported definitions that are visible at any given point in your code. Other languages use search-based code navigation, which searches all definitions and references across a repository to find entities with a given name. Both strategies are effective at finding results and both make sure to avoid inappropriate results such as comments, but precise code navigation can give more accurate results, especially when a repository contains multiple methods or functions with the same name.
- https://pl.ewi.tudelft.nl/research/projects/scope-graphs/
  - > Scope Graphs | A Theory of Name Resolution
  - > Scope graphs provide a new approach to defining the name binding rules of programming languages. A scope graph represents the name binding facts of a program using the basic concepts of declarations and reference associated with scopes that are connected by edges. Name resolution is defined by searching for paths from references to declarations in a scope graph. Scope graph diagrams provide an illuminating visual notation for explaining the bindings in programs.

## Symbolic / Concolic Execution

- https://en.wikipedia.org/wiki/Symbolic_execution
  - > In computer science, symbolic execution (also symbolic evaluation or symbex) is a means of analyzing a program to determine what inputs cause each part of a program to execute. An interpreter follows the program, assuming symbolic values for inputs rather than obtaining actual inputs as normal execution of the program would. It thus arrives at expressions in terms of those symbols for expressions and variables in the program, and constraints in terms of those symbols for the possible outcomes of each conditional branch. Finally, the possible inputs that trigger a branch can be determined by solving the constraints.
  - https://en.wikipedia.org/wiki/Symbolic_execution#Tools
  - https://en.wikipedia.org/wiki/Symbolic_execution#See_also
    - > Abstract interpretation
    - > Symbolic simulation
    - > Symbolic computation
    - > Concolic testing
    - > Control-flow graph
    - > Dynamic recompilation
- https://en.wikipedia.org/wiki/Concolic_testing
  - > Concolic testing (a portmanteau of concrete and symbolic, also known as dynamic symbolic execution) is a hybrid software verification technique that performs symbolic execution, a classical technique that treats program variables as symbolic variables, along a concrete execution (testing on particular inputs) path. Symbolic execution is used in conjunction with an automated theorem prover or constraint solver based on constraint logic programming to generate new concrete inputs (test cases) with the aim of maximizing code coverage. Its main focus is finding bugs in real-world software, rather than demonstrating program correctness.
  - > Implementation of traditional symbolic execution based testing requires the implementation of a full-fledged symbolic interpreter for a programming language. Concolic testing implementors noticed that implementation of full-fledged symbolic execution can be avoided if symbolic execution can be piggy-backed with the normal execution of a program through instrumentation. This idea of simplifying implementation of symbolic execution gave birth to concolic testing.
  - > An important reason for the rise of concolic testing (and more generally, symbolic-execution based analysis of programs) in the decade since it was introduced in 2005 is the dramatic improvement in the efficiency and expressive power of SMT Solvers. The key technical developments that lead to the rapid development of SMT solvers include combination of theories, lazy solving, DPLL(T) and the huge improvements in the speed of SAT solvers. SMT solvers that are particularly tuned for concolic testing include Z3, STP, Z3str2, and Boolector.
    - https://en.wikipedia.org/wiki/Satisfiability_modulo_theories
      - > In computer science and mathematical logic, satisfiability modulo theories (SMT) is the problem of determining whether a mathematical formula is satisfiable. It generalizes the Boolean satisfiability problem (SAT) to more complex formulas involving real numbers, integers, and/or various data structures such as lists, arrays, bit vectors, and strings. The name is derived from the fact that these expressions are interpreted within ("modulo") a certain formal theory in first-order logic with equality (often disallowing quantifiers). SMT solvers are tools that aim to solve the SMT problem for a practical subset of inputs. SMT solvers such as Z3 and cvc5 have been used as a building block for a wide range of applications across computer science, including in automated theorem proving, program analysis, program verification, and software testing.
    - https://en.wikipedia.org/wiki/Boolean_satisfiability_problem#Algorithms_for_solving_SAT
  - https://en.wikipedia.org/wiki/Concolic_testing#Algorithm
    - > Essentially, a concolic testing algorithm operates as follows:
      > 
      > - Classify a particular set of variables as input variables. These variables will be treated as symbolic variables during symbolic execution. All other variables will be treated as concrete values.
      > - Instrument the program so that each operation which may affect a symbolic variable value or a path condition is logged to a trace file, as well as any error that occurs.
      > - Choose an arbitrary input to begin with.
      > - Execute the program.
      > - Symbolically re-execute the program on the trace, generating a set of symbolic constraints (including path conditions).
      > - Negate the last path condition not already negated in order to visit a new execution path. If there is no such path condition, the algorithm terminates.
      > - Invoke an automated satisfiability solver on the new set of path conditions to generate a new input. If there is no input satisfying the constraints, return to step 6 to try the next execution path.
      > - Return to step 4.
      >
      > There are a few complications to the above procedure:
      > 
      > - The algorithm performs a depth-first search over an implicit tree of possible execution paths. In practice programs may have very large or infinite path trees – a common example is testing data structures that have an unbounded size or length. To prevent spending too much time on one small area of the program, the search may be depth-limited (bounded).
      > - Symbolic execution and automated theorem provers have limitations on the classes of constraints they can represent and solve. For example, a theorem prover based on linear arithmetic will be unable to cope with the nonlinear path condition xy = 6. Any time that such constraints arise, the symbolic execution may substitute the current concrete value of one of the variables to simplify the problem. An important part of the design of a concolic testing system is selecting a symbolic representation precise enough to represent the constraints of interest.
  - https://en.wikipedia.org/wiki/Concolic_testing#Tools
    - Jalangi is an open-source concolic testing and symbolic execution tool for JavaScript. Jalangi supports integers and strings.
- https://en.wikipedia.org/wiki/Constraint_logic_programming
  - > Constraint logic programming
  - > Constraint logic programming is a form of constraint programming, in which logic programming is extended to include concepts from constraint satisfaction. A constraint logic program is a logic program that contains constraints in the body of clauses.
- https://en.wikipedia.org/wiki/Automated_theorem_proving
  - > Automated theorem proving
  - > Automated theorem proving (also known as ATP or automated deduction) is a subfield of automated reasoning and mathematical logic dealing with proving mathematical theorems by computer programs.
- https://github.com/ksluckow/awesome-symbolic-execution
  - > Awesome Symbolic Execution
    > A curated list of awesome symbolic execution resources including essential research papers, lectures, videos, and tools.
- https://angr.io/
  - > angr
    > angr is an open-source binary analysis platform for Python. It combines both static and dynamic symbolic ("concolic") analysis, providing tools to solve a variety of tasks.
  - > Features:
    > - Symbolic Execution: Provides a powerful symbolic execution engine, constraint solving, and instrumentation.
    > - Control-Flow Graph Recovery: Provides advanced analysis techniques for control-flow graph recovery.
    > - Disassembly & Lifting: Provides convenient methods to disassemble code and lift to an intermediate language.
    > - Decompilation: Decompile machine code to angr Intermediate Language (AIL) and C pseudocode.
    > - Architecture Support: Supports analysis of several CPU architectures, loading from several executable formats.
    > - Extensibility: Provides powerful extensibility for analyses, architectures, platforms, exploration techniques, hooks, and more.
  - https://docs.angr.io/en/latest/
    - > Welcome to angr’s documentation!
    - > Welcome to angr’s documentation! This documentation is intended to be a guide for learning angr, as well as a reference for the API.
  - https://angr.io/blog/
  - https://github.com/angr
    - > angr: Next-generation binary analysis framework!
    - https://github.com/angr/angr
      - > angr
      - > A powerful and user-friendly binary analysis platform!
    - https://github.com/angr/angr-management
      - > angr Management
      - > The official angr GUI
    - https://github.com/angr/cle
      - > CLE
      - > CLE Loads Everything (at least, many binary formats!)
      - > CLE loads binaries and their associated libraries, resolves imports and provides an abstraction of process memory the same way as if it was loader by the OS's loader.
      - https://github.com/angr/cle#usage-example
- https://github.com/Z3Prover/z3
  - > The Z3 Theorem Prover
  - https://github.com/Z3Prover/z3/wiki
    - > Z3 is an SMT solver and supports the SMTLIB format.
      - https://smtlib.cs.uiowa.edu/
        - > SMT-LIB is an international initiative aimed at facilitating research and development in Satisfiability Modulo Theories (SMT).
        - > Documents describing the SMT-LIB input/output language for SMT solvers and its semantics;
        - etc
  - https://microsoft.github.io/z3guide/
    - > Online Z3 Guide
    - https://github.com/microsoft/z3guide
      - > Tutorials and courses for Z3
      - https://microsoft.github.io/z3guide/docs/logic/intro/
        - > Introduction
          > Z3 is a state-of-the art theorem prover from Microsoft Research. It can be used to check the satisfiability of logical formulas over one or more theories. Z3 offers a compelling match for software analysis and verification tools, since several common software constructs map directly into supported theories.
          > 
          > The main objective of the tutorial is to introduce the reader on how to use Z3 effectively for logical modeling and solving. The tutorial provides some general background on logical modeling, but we have to defer a full introduction to first-order logic and decision procedures to text-books in order to develop an in depth understanding of the underlying concepts. To clarify: a deep understanding of logical modeling is not necessarily required to understand this tutorial and modeling with Z3, but it is necessary to understand for writing complex models.
      - https://microsoft.github.io/z3guide/programming/Z3%20JavaScript%20Examples/
        - > Z3 JavaScript
          > The Z3 distribution comes with TypeScript (and therefore JavaScript) bindings for Z3. In the following we give a few examples of using Z3 through these bindings. You can run and modify the examples locally in your browser.
- https://github.com/Samsung/jalangi2
  - > Dynamic analysis framework for JavaScript
  - > Jalangi2 is a framework for writing dynamic analyses for JavaScript. Jalangi1 is still available at https://github.com/SRA-SiliconValley/jalangi, but we no longer plan to develop it. Jalangi2 does not support the record/replay feature of Jalangi1. In the Jalangi2 distribution you will find several analyses:
    > 
    > - an analysis to track NaNs.
    > - an analysis to check if an undefined is concatenated to a string.
    > - Memory analysis: a memory-profiler for JavaScript and HTML5.
    > - DLint: a dynamic checker for JavaScript bad coding practices.
    > - JITProf: a dynamic JIT-unfriendly code snippet detection tool.
    > - `analysisCallbackTemplate.js`: a template for writing a dynamic analysis.
    > - and more ...
    > 
    > See our tutorial slides for a detailed overview of Jalangi and some client analyses.
  - https://github.com/Samsung/jalangi2#usage
    - > Usage
    - > Analysis in node.js with on-the-fly instrumentation
    - > Analysis in node.js with explicit one-file-at-a-time offline instrumentation
    - > Analysis in a browser using a proxy and on-the-fly instrumentation
- https://github.com/SRA-SiliconValley/jalangi
  - > This repository has been archived by the owner on Dec 9, 2017. It is now read-only.
  - > We encourage you to switch to Jalangi2 available at https://github.com/Samsung/jalangi2. Jalangi2 is a framework for writing dynamic analyses for JavaScript. Jalangi2 does not support the record/replay feature of Jalangi1. Jalangi1 is still available from this website, but we no longer plan to develop it.
  - > Jalangi is a framework for writing heavy-weight dynamic analyses for JavaScript. Jalangi provides two modes for dynamic program analysis: an online mode (a.k.a direct or inbrowser analysis mode)and an offilne mode (a.k.a record-replay analysis mode). In both modes, Jalangi instruments the program-under-analysis to insert callbacks to methods defined in Jalangi. An analysis writer implements these methods to perform custom dynamic program analysis. In the online mode, Jalangi performs analysis during the execution of the program. An analysis in online mode can use shadow memory to attach meta information with every memory location. The offilne mode of Jalangi incorporates two key techniques: 1) selective record-replay, a technique which enables to record and to faithfully replay a user-selected part of the program, and 2) shadow values and shadow execution, which enables easy implementation of heavy-weight dynamic analyses. Shadow values allow an analysis to attach meta information with every value. In the distribution you will find several analyses:
    > 
    > - concolic testing,
    > - an analysis to track origins of nulls and undefined,
    > - an analysis to infer likely types of objects fields and functions,
    > - an analysis to profile object allocation and usage,
    > - a simple form of taint analysis,
    > - an experimental pure symbolic execution engine (currently undocumented)
- https://github.com/ExpoSEJS/ExpoSE
  - > ExpoSE
  - > A Dynamic Symbolic Execution (DSE) engine for JavaScript. ExpoSE is highly scalable, compatible with recent JavaScript standards, and supports symbolic modelling of strings and regular expressions.
  - > ExpoSE is a dynamic symbolic execution engine for JavaScript, developed at Royal Holloway, University of London by Blake Loring, Duncan Mitchell, and Johannes Kinder (now at LMU Munich). ExpoSE supports symbolic execution of Node.js programs and JavaScript in the browser. ExpoSE is based on Jalangi2 and the Z3 SMT solver.
- https://dl.acm.org/doi/10.1145/2635868.2635913
  - > SymJS: automatic symbolic testing of JavaScript web applications (2014)
  - > We present SymJS, a comprehensive framework for automatic testing of client-side JavaScript Web applications. The tool contains a symbolic execution engine for JavaScript, and an automatic event explorer for Web pages. Without any user intervention, SymJS can automatically discover and explore Web events, symbolically execute the associated JavaScript code, refine the execution based on dynamic feedbacks, and produce test cases with high coverage. The symbolic engine contains a symbolic virtual machine, a string-numeric solver, and a symbolic executable DOM model. SymJS's innovations include a novel symbolic virtual machine for JavaScript Web, symbolic+dynamic feedback directed event space exploration, and dynamic taint analysis for enhancing event sequence construction. We illustrate the effectiveness of SymJS on standard JavaScript benchmarks and various real-life Web applications. On average SymJS achieves over 90% line coverage for the benchmark programs, significantly outperforming existing methods.
- https://github.com/javert2/JaVerT2.0
  - > JaVerT2.0 - Compositional Symbolic Execution for JavaScript
  - > JaVerT: JavaScript Verification Toolchain
      > JaVerT (pronounced [ʒavɛʁ]) is a toolchain for semi-automatic verification of functional correctness properties of JavaScript programs. It is based on separation logic.
  - > Deprected - Please use Gillian-JS instead
    > We've built a generalised version of JaVerT2.0 called Gillian, which is currently hosted at https://github.com/GillianPlatform/Gillian
    - https://github.com/GillianPlatform/Gillian
      - > The Gillian Platform main repository
      - https://gillianplatform.github.io/
        - https://gillianplatform.github.io/sphinx/c/index.html
          - > Gillian-C
          - > Gillian-C is the instantiation of Gillian to the C language (CompCert-C, to be precise). It can be found in the Gillian-C folder of the repository.
        - https://gillianplatform.github.io/sphinx/js/index.html
          - > Gillian-JS
          - > Gillian-JS is the instantiation of Gillian to JavaScript (ECMAScript 5 Strict), found in the Gillian-JS folder of the repository.
          - > Danger: Gillian-JS is currently broken (see here).
            - https://github.com/GillianPlatform/Gillian/issues/113
              - > Gillian-JS is broken
            - https://github.com/GillianPlatform/Gillian/pull/229
              - > Fix JS
            - https://github.com/GillianPlatform/Gillian/issues/237
              - > Fix Amazon JS
              - https://github.com/GillianPlatform/Gillian/pull/238
                - > Fix Amazon JS verification
  - https://www.doc.ic.ac.uk/~pg/publications/FragosoSantos2019JaVerT.pdf
    - > JaVerT 2.0: Compositional Symbolic Execution for JavaScript (2019)
    - > We propose a novel, unified approach to the development of compositional symbolic execution tools, bridging the gap between classical symbolic execution and compositional program reasoning based on separation logic. Using this approach, we build JaVerT 2.0, a symbolic analysis tool for JavaScript that follows the language semantics without simplifications. JaVerT 2.0 supports whole-program symbolic testing, verification, and, for the first time, automatic compositional testing based on bi-abduction. The meta-theory underpinning JaVerT 2.0 is developed modularly, streamlining the proofs and informing the implementation. Our explicit treatment of symbolic execution errors allows us to give meaningful feedback to the developer during wholeprogram symbolic testing and guides the inference of resource of the bi-abductive execution. We evaluate the performance of JaVerT 2.0 on a number of JavaScript data-structure libraries, demonstrating: the scalability of our whole-program symbolic testing; an improvement over the state-of-the-art in JavaScript verification; and the feasibility of automatic compositional testing for JavaScript.
- https://webblaze.cs.berkeley.edu/2010/kudzu/kudzu.pdf
  - > A Symbolic Execution Framework for JavaScript (2010)
  - > As AJAX applications gain popularity, client-side JavaScript code is becoming increasingly complex. However, few automated vulnerability analysis tools for JavaScript exist. In this paper, we describe the first system for exploring the execution space of JavaScript code using symbolic execution. To handle JavaScript code’s complex use of string operations, we design a new language of string constraints and implement a solver for it. We build an automatic end-to-end tool, Kudzu, and apply it to the problem of finding client-side code injection vulnerabilities. In experiments on 18 live web applications, Kudzu automatically discovers 2 previously unknown vulnerabilities and 9 more that were previously found only with a manually-constructed test suite.
- https://www.code-intelligence.com/blog/using-symbolic-execution-fuzzing
  - > Why You Should Combine Symbolic Execution and Fuzzing
  - > As opposed to traditional fuzzers, which generate inputs without taking code structure into account, symbolic execution tools precisely capture the computation of each value. They use solvers at each branch to generate new inputs and thus to provide the precisely calculated input to cover all parts of code.
  - > Symbolic Execution Tools
    > - KLEE: KLEE is an open-source code testing instrument that runs on LLVM bitcode, a representation of the program created by the clang compiler. KLEE explores the program and generates test cases to reproduce any crashes it finds.
    > - > Driller
    >   > Driller is a concolic execution tool. Concolic execution is a software testing technique that performs symbolic execution (using symbolic input values with sets of expressions, one expression per output variable) with concrete execution (testing on particular inputs) path. The advantage of this approach is that it can achieve high code coverage even in case of complex source code, but still maintain a high degree of scalability and speed.
    >   > 
    >   > Driller uses selective concolic execution to explore only the paths that are found interesting by the fuzzer and to generate inputs for conditions (branches) that a fuzzer cannot satisfy. In other words, it leverages concolic execution to reach deeper program code but uses a feedback-driven/guided fuzzer to alleviate path explosion, which greatly increases the speed of the testing process.
  - > Although Driller marked significant research advances in the field of symbolic execution, it is still a highly specialized tool that requires expert knowledge to set up and run and uses up a lot of computational resources. So, how can the industry profit from the latest research?
    > 
    > Driller and other symbolic or concolic execution tools can be paired with open-source fuzzing tools. Contrary to many traditional fuzzers, modern fuzzers such as AFL++ or libfuzzer do not just generate random inputs. Instead, they use intelligent algorithms to provide inputs that reach deeper into the code structure. Enhancing such fuzzers with concolic execution is highly effective in cases when fuzzing algorithms reach their limits.
    - https://github.com/AFLplusplus/AFLplusplus
      - > American Fuzzy Lop plus plus (AFL++)
      - > The fuzzer afl++ is afl with community patches, qemu 5.1 upgrade, collision-free coverage, enhanced laf-intel & redqueen, AFLfast++ power schedules, MOpt mutators, unicorn_mode, and a lot more!
      - https://aflplus.plus/
        - > AFL++ Overview
          > AFLplusplus is the daughter of the American Fuzzy Lop fuzzer by Michał “lcamtuf” Zalewski and was created initially to incorporate all the best features developed in the years for the fuzzers in the AFL family and not merged in AFL cause it is not updated since November 2017.
    - https://llvm.org/docs/LibFuzzer.html
      - > libFuzzer – a library for coverage-guided fuzz testing
      - > LibFuzzer is an in-process, coverage-guided, evolutionary fuzzing engine.
        > 
        > LibFuzzer is linked with the library under test, and feeds fuzzed inputs to the library via a specific fuzzing entrypoint (aka “target function”); the fuzzer then tracks which areas of the code are reached, and generates mutations on the corpus of input data in order to maximize the code coverage. The code coverage information for libFuzzer is provided by LLVM’s SanitizerCoverage instrumentation.

## Profiling

- See also, the notes from ChatGPT ([Ref](https://chat.openai.com/c/9ce9613d-50c1-4a66-9d0b-08c1df037361)) that I captured in this comment: https://github.com/pionxzh/wakaru/issues/35#issuecomment-1818366313
  - https://nodejs.org/en/docs/guides/diagnostics-flamegraph
  - https://github.com/davidmarkclements/0x
    - > single-command flamegraph profiling 🔥
      > Discover the bottlenecks and hot paths in your code, with flamegraphs
  - https://github.com/clinicjs/node-clinic
    - > Clinic.js diagnoses your Node.js performance issues
    - https://clinicjs.org/
      - > Tools to help diagnose and pinpoint Node.js performance issues
      - https://clinicjs.org/doctor/
        - > Clinic.js Doctor: Diagnose performance issues in your Node.js applications
      - https://clinicjs.org/bubbleprof/
        - > Clinic.js Bubbleprof: Bubbleprof is a new, completely unique, approach to profiling your Node.js code
        - https://clinicjs.org/blog/introducing-bubbleprof/
          - > Introducing Bubbleprof - a novel approach to Node.js async profiling
      - https://clinicjs.org/flame/
        - > Clinic.js Flame: Uncovers the bottlenecks and hot paths in your code with flamegraphs
      - https://clinicjs.org/heapprofiler/
        - Clinic.js HeapProfiler: Uncovers memory allocations by functions with Flamegraphs.

## Unsorted

- https://github.com/bytecodealliance/ComponentizeJS
  - > ESM -> WebAssembly Component creator, via a SpiderMonkey JS engine embedding
  - > Provides a Mozilla SpiderMonkey embedding that takes as input a JavaScript source file and a WebAssembly Component WIT World, and outputs a WebAssembly Component binary with the same interface.
  - https://bytecodealliance.org/articles/making-javascript-run-fast-on-webassembly
    - > Making JavaScript run fast on WebAssembly
    - > We should be clear here—if you’re running JavaScript in the browser, it still makes the most sense to simply deploy JS. The JS engines within the browsers are highly tuned to run the JS that gets shipped to them.
  - https://github.com/bytecodealliance/wizer
    - > The WebAssembly Pre-Initializer
      > Don't wait for your Wasm module to initialize itself, pre-initialize it! Wizer instantiates your WebAssembly module, executes its initialization function, and then snapshots the initialized state out into a new WebAssembly module. Now you can use this new, pre-initialized WebAssembly module to hit the ground running, without making your users wait for that first-time set up code to complete.
      > 
      > The improvements to start up latency you can expect will depend on how much initialization work your WebAssembly module needs to do before it's ready. Some initial benchmarking shows between 1.35 to 6.00 times faster instantiation and initialization with Wizer, depending on the workload
- https://wingolog.org/archives/2022/08/18/just-in-time-code-generation-within-webassembly
  - > just-in-time code generation within webassembly
- https://github.com/WebAssembly/wabt
  - > The WebAssembly Binary Toolkit
  - > WABT (we pronounce it "wabbit") is a suite of tools for WebAssembly, including:
    > 
    > - `wat2wasm`: translate from WebAssembly text format to the WebAssembly binary format
    > - `wasm2wat`: the inverse of wat2wasm, translate from the binary format back to the text format (also known as a .wat)
    > - `wasm-objdump`: print information about a wasm binary. Similiar to objdump.
    > - `wasm-interp`: decode and run a WebAssembly binary file using a stack-based interpreter
    > - `wasm-decompile`: decompile a wasm binary into readable C-like syntax.
    > - `wat-desugar`: parse .wat text form as supported by the spec interpreter (s-expressions, flat syntax, or mixed) and print "canonical" flat format
    > - `wasm2c`: convert a WebAssembly binary file to a C source and header
    > - `wasm-strip`: remove sections of a WebAssembly binary file
    > - `wasm-validate`: validate a file in the WebAssembly binary format
    > - `wast2json`: convert a file in the wasm spec test format to a JSON file and associated wasm binary files
    > - `wasm-stats`: output stats for a module
    > - `spectest-interp`: read a Spectest JSON file, and run its tests in the interpreter
    > 
    > These tools are intended for use in (or for development of) toolchains or other systems that want to manipulate WebAssembly files. Unlike the WebAssembly spec interpreter (which is written to be as simple, declarative and "speccy" as possible), they are written in C/C++ and designed for easier integration into other systems. Unlike Binaryen these tools do not aim to provide an optimization platform or a higher-level compiler target; instead they aim for full fidelity and compliance with the spec (e.g. 1:1 round-trips with no changes to instructions).

## My ChatGPT Research / Conversations

These are private chat links, so won't work for others, and are included here only for my reference:

- [Webpack Minification Noise](https://chat.openai.com/c/e65996fc-6607-4209-a082-6bc086c4f043)

## See Also

### My Other Related Deepdive Gist's and Projects

- https://github.com/0xdevalias/chatgpt-source-watch : Analyzing the evolution of ChatGPT's codebase through time with curated archives and scripts.
  - [Reverse engineering ChatGPT's frontend web app + deep dive explorations of the code (0xdevalias gist)](https://gist.github.com/0xdevalias/4ac297ee3f794c17d0997b4673a2f160#reverse-engineering-chatgpts-frontend-web-app--deep-dive-explorations-of-the-code)
- [Reverse Engineering Webpack Apps (0xdevalias gist)](https://gist.github.com/0xdevalias/8c621c5d09d780b1d321bfdb86d67cdd#reverse-engineering-webpack-apps)
- [Reverse Engineered Webpack Tailwind-Styled-Component (0xdevalias gist)](https://gist.github.com/0xdevalias/916e4ababd3cb5e3470b07a024cf3125#reverse-engineered-webpack-tailwind-styled-component)
- [React Server Components, Next.js v13+, and Webpack: Notes on Streaming Wire Format (`__next_f`, etc) (0xdevalias' gist))](https://gist.github.com/0xdevalias/ac465fb2f7e6fded183c2a4273d21e61#react-server-components-nextjs-v13-and-webpack-notes-on-streaming-wire-format-__next_f-etc)
- [Fingerprinting Minified JavaScript Libraries / AST Fingerprinting / Source Code Similarity / Etc (0xdevalias gist)](https://gist.github.com/0xdevalias/31c6574891db3e36f15069b859065267#fingerprinting-minified-javascript-libraries--ast-fingerprinting--source-code-similarity--etc)
- [Bypassing Cloudflare, Akamai, etc (0xdevalias gist)](https://gist.github.com/0xdevalias/b34feb567bd50b37161293694066dd53#bypassing-cloudflare-akamai-etc)
- [Debugging Electron Apps (and related memory issues) (0xdevalias gist)](https://gist.github.com/0xdevalias/428e56a146e3c09ec129ee58584583ba#debugging-electron-apps-and-related-memory-issues)
- [devalias' Beeper CSS Hacks (0xdevalias gist)](https://gist.github.com/0xdevalias/3d2f5a861335cc1277b21a29d1285cfe#beeper-custom-theme-styles)
- [Reverse Engineering Golang (0xdevalias' gist)](https://gist.github.com/0xdevalias/4e430914124c3fd2c51cb7ac2801acba#reverse-engineering-golang)
- [Reverse Engineering on macOS (0xdevalias' gist)](https://gist.github.com/0xdevalias/256a8018473839695e8684e37da92c25#reverse-engineering-on-macos)
