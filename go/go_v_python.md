Go compared to Python for small scale system administration scripts and tools
January 24, 2020
We write a certain amount of scripts and tools around here. I like Go and have used it for a while, we have some tools already written in Go, and while I'm also a long term user of Python I'm on record as being unhappy with various developments around Python 3. Despite all of this, Python is the programming language I default to when I need to do something that's more complicated than a shell script (and not because of our policy on internal tools). Over time I've come to believe that Python has some important pragmatic properties in our sort of relatively small scale environment with generally modest use of local tools, despite Go's collection of appealing properties.

The first useful property Python has is that you can't misplace the source code for your deployed Python programs. Unless you do something very peculiar, what you deploy is the source code (well, a version of it). With Go you deploy a compiled artifact, which means that you may someday have to find the source code and then try to match your compiled binary up against some version of it. Of course your deployed Python program can drift out of sync with the master copy in your version control repository, but sorting that out only requires use of diff.

Closely related to this is that Python code is generally simple for people to modify and re-deploy. Modest Python scripts and tools are likely to be only a single .py file, which you can edit and copy around, and even somewhat bigger ones are likely to just be a directory that can be copied. Deploying Go code requires not just the correct source code but also a Go development environment and the knowledge of how to build Go programs from source. With Python, you can even try things out by just modifying the deployed version in place, then back-port your eventual changes to the official master copy in your version control system.

(These days Go's support for modules makes all of this simpler than it used to be, but there are still important considerations and some potential complexities.)

I further feel that for people who're only mildly familiar with the language, Python code is easier to make minor modifications to. Python's dynamic typing makes for a relatively forgiving environment for many quick things or small changes. Python 3 throws a small spanner into this with its insistence that you absolutely can't mix spaces and tabs (go on, try to explain that one to someone who's just quickly adding a line in a general editor without being familiar with Python). Between the language and the requirement for compiling things, Go puts a higher bar in for quick changes to fix up some issue.

(As a corollary, I think that Go code in a small environment is much more likely to wind up being 'owned' by only one person, with everyone else relying on them for any changes no matter how small. This is a natural outcome of needing more specialized knowledge to work with the Go code.)

These things aren't issues for Go if you've already made a commitment to it. If you have plenty of larger scale tools written in Go because of its advantages (or you've just standardized on it), you'll already have solved all of these problems; you're keeping track of source code and versions, people know Go and have build environments, everyone can confidently change Go code, and so on.

(And once you're used to the simplicity of copying a single self contained binary artifact around, various aspects of the Python experience of working with lots of modules will irritate you.)

Overall, my view is that Go is a 'go big or go home' language for system administration tools. It works at the large scale quite well, but it doesn't necessarily scale down to occasional use for small things in the way that Python scripts can. Python scripts tolerate casual environments much more readily than Go does. Most smaller scale environments like ours won't be able to commit to Go this way, if only because we simply don't do all that much programming on an ongoing basis.

(This is related to the convenience of people writing commands in Python.)

Sidebar: My view on writing small tools
I also feel that it's simpler and faster to develop relatively small programs in Python than in Go. If I want to process some text in a way that's a bit too complicated for a sensible shell script (for example), Python gives me an environment where it's very easy to put something together and then iterate rapidly on it as I come to understand more about what I want (and the problem). Using Go would put a lot more up front work in the way of running code that solves my problem. All of this makes it more natural (for me) to use Python for small programs, such as parsing program output to generate VPN activity metrics.

(Large programs unquestionably benefit from the discipline that Go requires. It's possible to write clean large Python programs, but it's also easy to let them drift into awkward, 1600 line tangled semi-monstrosities as they grow step by step.)
