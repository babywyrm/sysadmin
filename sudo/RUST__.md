	Hacker News new | past | comments | ask | show | jobs | submit	login

 ##
 https://news.ycombinator.com/item?id=25921592
 ##

comex on Jan 26, 2021 | parent | context | favorite | on: Heap-based buffer overflow in Sudo

But if sudo were written in Rust, it could have the same level of complexity and not be vulnerable.
Yes, it would still be vulnerable to logic errors, like the last famous sudo bug where you pass -1 as the UID. But it wouldn't be vulnerable to this. (And this isn't the first memory safety bug to be found in sudo.)

Yes, sudo's complexity is useless for 99.99% of its users. But wouldn't it be nice if the result were merely a gross feeling rather than a security hole?



	
musicale on Jan 26, 2021 | next [–]

> But if sudo were written in Rust, it could have the same level of complexity and not be vulnerable
I'm puzzled that we don't have a memory-safe ABI (e.g. amd64-safe) and runtime for C so we could just compile things with

    clang -safe sudo.c
to avoid memory errors. I'm fine with sudo (or whatever) taking a 60% performance hit to be more reliable - processors are thousands of times faster now than they were in 1980 when sudo was written. If we had a memory-safe ABI for C/C++ in common use its performance overhead could probably be reduced significantly over time due to implementation improvements, and we might see hardware acceleration for it as well.
There are a number of proof-of-concept memory-safe compilers for C using fat pointers, etc., but memory safety hasn't made it into gcc or clang. 64-bit CPUs can help because you can repurpose address bits. Even Pascal (which is largely isometric to C) supported a degree of memory safety via array bounds checking. I believe Ada compilers also support memory safety. PL/I was actually memory safe and is why Multics never had any buffer overflows. Obviously Rust is memory safe, but for a lot of legacy C code it is impractical to rewrite everything in Rust but eminently practical to recompile it with memory safety turned on.


	
roca on Jan 27, 2021 | parent | next [–]

Encoding array bounds into fat pointers doesn't always work without changing code (e.g. code that uses funky casts, code that makes assumptions about data layout).
Also to ship this in a Linux distro you'd need two builds of many packages. Tons of tools would need to be updated to work with the new ABI. It would be a nightmare.

Furthermore, a new fat-pointer ABI would not address lifetime errors like use-after-free, so what would your plan be there? Boehm GC? More complexity, more overhead, more compatibility issues.

So in practice this is not that appealing, which is why we don't do it.


	
scaramanga on Jan 27, 2021 | root | parent | next [–]

I think the practical issues you describe like rebuilds of packages and so on are very real if we're talking about general adoption. But if we're talking about recompiling a handful of SUID programs which make up a TCB then I think a proposition like that has a lot of merit and can't be easily dismissed.
Any C code that needs changing to deal with fat-pointers is probably already UB in C (or at best, has some implementation-defined behaviour).

That's because the representation of pointers themselves is undefined (so you can't get a valid result by looking at those). Pointer/integer casts (either direction) are implementation defined. And accesses via pointers to anything beyond their bounds is already UB.

There's some good and interesting discussion of what's involved in all of this on: https://www.ralfj.de/blog/2020/12/14/provenance.html

And there's already bodies of work within the Rust (and C/C++) communities around the concepts/technologies that would need to be developed to achieve something like a memory-safe UNIX TCB.


	
roca on Jan 27, 2021 | root | parent | next [–]

If we're talking about recompiling a handful of SUID programs, why not just manually translate them into Rust or something similar?

	
scaramanga on Jan 27, 2021 | root | parent | next [–]

Yes, that's probably a good idea.
But it comes with costs. Someone has to learn Rust and then convert all of these programs. And it also has the issue that Rust programs are only memory safe if the unsafe keyword is not used anywhere in the program (correct me if wrong?). So it looks like the effort to do such thing, while noble, and valiant, is essentially an experiment with an uncertain pay-off that could turn out to be small or large.

Much more interesting (to my mind, anyway) is something like Miri. The rust interpreter, which uses fat-pointers to make things (more? completely? someone more informed can correct me..) memory-safe by inserting some relatively lightweight run-time checks.

And, then again, if such a thing could be compiled rather than interpreted (some things similar to this already exist, like C with fat-pointers). And if the source language was C (or something like it) or C++ (or some future C++) then the human aspect of re-training a generation of programmers goes from being a very big hurdle, to a much lower one.

At that point the benefits go up quite a bit, and the costs come down quite a bit. And I think that might be a promising path to overcoming the sort of human/political hurdles/inertia involved in rewriting the world :)


	
roca on Jan 27, 2021 | root | parent | next [–]

You can definitely implement sudo and similar tools without writing any new unsafe code.
You will use existing libraries that contain unsafe code, but you should be able to stick to popular well-tested libraries, which means it will be very difficult for an attacker to find a new exploitable bug in those libraries to attack your tools.


	
meithecatte on Jan 27, 2021 | root | parent | prev | next [–]

> But it comes with costs. Someone has to learn Rust and then convert all of these programs.
Someone has to learn compiler engineering and then design and implement a 'safe' ABI. Unlike learning Rust, this is probably worthy of a research paper.

> Rust programs are only memory safe if the unsafe keyword is not used anywhere in the program

If you use unsafe, then you take some of the responsibility for maintaining memory safety. However, you can audit the unsafe parts of the code, and it will compose with the compiler-provided guarantees for the rest of the code. Besides, one can easily avoid unsafe code for safety-critical tools like these.

> Much more interesting (to my mind, anyway) is something like Miri. The rust interpreter, which uses fat-pointers to make things (more? completely? someone more informed can correct me..) memory-safe by inserting some relatively lightweight run-time checks.

Miri does not support most interaction with the outside world [1]. It is focused more on detecting UB in unsafe code when it is exercised by tests, than on having your code running in production through Miri. Moreover, I wouldn't call a thousand-fold slowdown [2] "relatively lightweight".

[1]: https://github.com/rust-lang/miri#miri [2]: https://www.reddit.com/r/rust/comments/hosvqu/will_the_miri_...


	
scaramanga on Jan 28, 2021 | root | parent | next [–]

> Someone has to learn compiler engineering and then design and implement a 'safe' ABI. Unlike learning Rust, this is probably worthy of a research paper.
Yes, all good points. What I'm getting at is that it seems like nobody has yet re-written sudo in this safe way. And it's not just a matter of re-writing it. If (when) someone comes along with this re-write there's "if this person goes away, will we find someone else to maintain it?" and all those other very conservative social forces at play.

I think any new programming language community has these sorts of adoption hurdles to face. And I'm sure the rust community is working hard to build up that pool of developers and I think that's all really positive so I don't want to sound like I'm subtracting from it at all. I'm just also an interested spectator of PL and systems programming research/new directions :)

> If you use unsafe, then you take some of the responsibility for maintaining memory safety. However, you can audit the unsafe parts of the code, and it will compose with the compiler-provided guarantees for the rest of the code. Besides, one can easily avoid unsafe code for safety-critical tools like these.

Thanks, yep. That's why I think that generally Rust is a good idea, and rewriting the TCB in it is a worthwhile project. In regards to safety it looks like a step in the right direction. We're just quibbling about the cost/benefit analysis of how big of a step it is compared to above-mentioned issues that all new programming languages face. Personally, I've no doubt that even with all that factored in, it's still a net positive.

> Miri does not support most interaction with the outside world [1]. It is focused more on detecting UB in unsafe code when it is exercised by tests, than on having your code running in production through Miri. Moreover, I wouldn't call a thousand-fold slowdown [2] "relatively lightweight"

Thanks for the clarifications, you're definitely more up to speed on that project than I am! But yeah, what I meant there was not that the implementation of miri was something to use as-is, more that it's an interesting direction in PL/systems programming research (imo). And some of the ideas there, especially where runtime cost _in principle_ can be made to be relatively lightweight are interesting. I've seen some other research where C implementations with bounds-checking have been implemented part-statically and where the remaining checks are done at run-time with fat-pointers.

OK, bounds checking isn't memory safety, but the paper was a while ago. Maybe it was this one https://www.comp.nus.edu.sg/~ryap/Projects/LowFat/ ?

So I mean, it sounds like you might be able to get to a place where you can use some bits of unsafe in rust, but maybe the program overall could still be safe because the compiler can have a mode where run-time checks (which can be statically eliminated in a lot of cases) are included.

But hey, I'm just a relatively amateur outside-observer of all this, maybe that's a totally impossible pipe dream? :)


	
kortex on Jan 27, 2021 | root | parent | prev | next [–]

> e.g. code that uses funky casts, code that makes assumptions about data layout
Maybe it shouldn't be doing that? Isn't that the whole point of something like a -safe flag? Increase security as you go along. Yes it is going to take time. The best time to plant a tree is 20 years ago, next best is today.


	
roca on Jan 27, 2021 | root | parent | next [–]

Maybe it shouldn't be doing that, but "recompiling C code in safe mode" only makes sense if you don't have to change the code much or at all.
If you have to make all kinds of changes to the code you might as well just translate it into a different language.


	
scatters on Jan 26, 2021 | parent | prev | next [–]

It's called AddressSanitizer. You enable it with the compiler flag -fsanitize=address. It's supported by clang, gcc and lately MSVC.

	
saagarjha on Jan 27, 2021 | root | parent | next [–]

Address Sanitizer is not perfect, nor is it suitable to ship in production.

	
kevingadd on Jan 27, 2021 | root | parent | prev | next [–]

Asan binaries should never be shipped in security sensitive environments. It's not designed for that. It's unsafe.

	
rkeene2 on Jan 26, 2021 | root | parent | prev | next [–]

You shouldn't use ASan in release builds since it may have exploitable vulnerabilities.

	
pjmlp on Jan 27, 2021 | root | parent | prev | next [–]

And used by around 36% of developers that bother to answer surveys.

	
roblabla on Jan 27, 2021 | parent | prev | next [–]

Compile it for wasm and use a wasm runtime built in a memory-safe language? I believe some wasm runtimes allow for making raw syscalls.

	
kaba0 on Jan 27, 2021 | root | parent | next [–]

It would not stop these sort of exploits if I’m not mistaken (ok, it could help since rewriting return addresses is not possible I think), but memory errors that cause logic bugs are still possible.

	
roca on Jan 27, 2021 | root | parent | next [–]

Yes, that's exactly right.

	
0xbadcafebee on Jan 27, 2021 | prev | next [–]

If sudo were written in Perl, it would also not be vulnerable.

	
MayeulC on Jan 27, 2021 | parent | next [–]

I thought about that. But when using a higher-level language (that comes with a runtime), you need to give privileges to the whole runtime, which arguably has a much bigger attack surface, unless I am mistaken?
The kernel won't allow you to setuid scripts, there is a reason for this: it's very easy to leave glaring security holes while doing so.


	
0xbadcafebee on Jan 27, 2021 | root | parent | next [–]

Perl had a fix for this called suidperl, which was a wrapper which enabled Taint mode and other strict checks (https://perldoc.perl.org/perlsec). I don't know of any other language or interpreter that go this far for security by default, so Perl might be the most secure language in this regard. However, suidperl was dropped in 5.12.
My main point was that you could rewrite sudo in all sorts of languages, but saying "just rewrite it in Perl" (assuming it worked) isn't a enough justification to make it happen. Nobody is going to re-create their own project in Perl, Rust, etc just to eliminate buffer overflows. If somebody wants sudo in Rust, they'll have to do it themselves, and it still might never replace the original.


	
MayeulC on Jan 27, 2021 | root | parent | next [–]

Thank you for pointing that out :)
If someone would get serious about security, auditing every setuid binary would certainly be something on their list (if they use any). If they really want the functionality, rewriting it to cover just enough of the required functionality wouldn't be unheard of.


	
0xbadcafebee on Jan 28, 2021 | root | parent | next [–]

I agree. But really the security best practice is to remove setuid from all binaries, and rely on RBAC rules (such as with SELinux). That would solve more security issues than anything else, but this is way more effort than most people are willing to invest in security.

	
ddevault on Jan 26, 2021 | prev | next [–]

>But if sudo were written in Rust, it could have the same level of complexity and not be vulnerable.
This is not true. Complexity breeds bugs, including security bugs, and memory safety doesn't change that. Your example is a good one - here's another: doas once failed to limit the environment variables which are passed to the child process, which could be used to nefariously influence the program running (e.g. with LD_PRELOAD). How would Rust prevent that oversight? It wouldn't.

A simpler program will generally be more secure than a complicated one, no matter what language either is written in. Furthermore, rewriting an established program from one language to another will always introduce more bugs than it fixes, and more severely the more complex the program is. The single best way to improve security is to reduce the attack surface, and the single best way to do that is to reduce the complexity of your system.


	
zamadatix on Jan 26, 2021 | parent | next [–]

If you go a little further with the quote:
"Yes, it would still be vulnerable to logic errors... But it wouldn't be vulnerable to this. "

I think you'll find in disagreeing with the comment on logic errors you just said the same thing the comment did about logic errors.

Also I think the generalization that rewriting an established bit of code in a new language in a secure language is a bit too general. clearly Firefox not only set out to make Rust for this purpose but it's not had an explosion in vulnerabilities with the modules it has replaced. Quite the opposite actually. Nor has every tool or app rewritten become a security failure compared to the original. I do think it's something that can easily be screwed up though, especially if someone rushes through by focusing on functionality duplication instead of building a more secure version of something.

Regardless, both "using a memory safe language results in a more safe program" and "having a minimum attack sufrace results in a more safe program" can be true. There is no need to make it a choice of A or B.


	
ddevault on Jan 26, 2021 | root | parent | next [–]

>I think you'll find in disagreeing with the comment on logic errors you just said the same thing the comment did about logic errors.
I think you'll find that my comment explicitly acknowledges this and expands on it with another example. Are we done telling each other to read the things we're writing?

>Firefox not only set out to make Rust for this purpose but it's not had an explosion in vulnerabilities with the modules it has replaced.

You're setting the bar pretty high with an "explosion" of vulnerabilities here. Rust programs have vulnerabilities, including rewrites. They also have other kinds of bugs, often ones which were not present in the code that they're replacing. You need only browse your nearest convenient RiiR bug tracker to find evidence of this.

Let me restate my thesis in mathematical terms. If we presume that 1 in 100 lines of production code has a bug in it, regardless of language (generous, I know), and that 1 in 10 bugs in C programs are memory corruption related, then saving 10% of those bugs by rewriting it in Rust would take a 10,000 line codebase from 100 bugs to 90 bugs. A 1,000 line codebase, still written in C and without the advantage of memory safety, would have only 10.

In today's example, sudo is a caricature of runaway complexity. Rust is often touted as a panacea, but C has very little to do with why sudo is insecure. Sudo is comically overengineered and that level of overengineering has no place in a security context. This is the larger issue that needs to be addressed, not Rust.


	
vitno on Jan 26, 2021 | root | parent | next [–]

I agree Rust is not a panacea and that rewrites create their own set of problems, the only issue with this analysis is assuming 1/10 bugs are memory corruption related.
Both Chrome & Microsoft found about 70% of bugs to be memory safety related. I've heard similar numbers out of FB as well. The math looks a little different with that data.

https://www.chromium.org/Home/chromium-security/memory-safet...

https://www.zdnet.com/article/microsoft-70-percent-of-all-se...


	
ddevault on Jan 26, 2021 | root | parent | next [–]

Even if we run the same math with 7 out of 10 bugs being memory safety related, and assuming that Rust prevents all of them, those same example programs end up with 30 bugs in Rust and 10 bugs in C.
There's another argument I could make, too. Look at the bug tracker for the program you want to rewrite in Rust, examining the historical bugs. You'll find that there are often hundreds or thousands of mistakes that they made and already fixed in the original codebase. If you're rewriting it from scratch, can you be sure you won't make just as many? A stable, maintained codebase with a low throughput of changes tends to have fewer bugs over time, as the lack of churn avoids introducing new bugs and the application of time susses out all of the existing bugs. Rewriting the whole thing from scratch has a very high rate of churn, introducing a whole new slew of bugs on its own.

Now, a small codebase, focused on delivering its key value-adds without distractions, kept stable and at a low-churn rate over a long period of time: no matter what language you use, this is the best recipe for reliability and security.


	
zamadatix on Jan 27, 2021 | root | parent | next [–]

So again why does it have to be "rewrite at 1/10th the complexity in <Language A>" (10%) vs "rewrite in <Language B> at full complexity" (30%)? What's preventing using Language B for the complexity rewrite and getting 0.1 * (1 - 0.7) = 3%?
Rewrites do bring the chance to Royally Screw it Up™ so it's certainly not simply a product of "it is now written in <Language X> therefore safe" but as it said not only have projects shown the security didn't fall apart but they have shown the opposite.

I agree you don't get there by a bunch of yolo rewrites to whatever is hip though, it has to be a planned effort that isn't rushed. Much in the same way quickly writing a small replacement utility does not inherently make it more secure or reliable than an existing significantly more complex utility. Even just trying to shave some functionality off the existing code is rife with "but how does removing this piece affect the app remaining logic" and takes time and effort to do right.

Both methods do have to be done right and both do greatly help security but there is nothing about picking a memory safe language or making a significantly narrower focused utility that preclude each other.


	
ddevault on Jan 27, 2021 | root | parent | next [–]

You can do both! But because simplicity has a substantially greater impact than the language choice, I think it's better to focus on that. Right now, the ecosystem is focusing more on the language choice, and hardly talking about simplicity at all. And particularly in the case of Rust, I think it fails simplicity a lot in its own ways - in the stdlib, the compiler and toolchain, the language design - and the trade-offs don't really make sense for a lot of use cases that people are pining for it over anyway.

	
myrrlyn on Jan 26, 2021 | root | parent | prev | next [–]

helps that a 10kloc c program getting riir'd probably won't be a 10kloc rust program, because c doesn't have libraries and rust does.
it is literally impossible to write "a small codebase focused on its key value-adds without distractions" in a language that doesn't have strings and requires you to build a dictionary from scratch


	
ddevault on Jan 26, 2021 | root | parent | next [–]

>helps that a 10kloc c program getting riir'd probably won't be a 10kloc rust program, because c doesn't have libraries and rust does.
What? Rust has so few libraries of significance that it still depends on C for security-critical areas like SSL.

>it is literally impossible to write "a small codebase focused on its key value-adds without distractions" in a language that doesn't have strings and requires you to build a dictionary from scratch

Strings are misunderstood, I'm not going to get into it here. My dictionaries in C usually clock in at about two dozen lines of code. The complexity doesn't go away because your language does it for you.


	
saagarjha on Jan 27, 2021 | root | parent | next [–]

Having written dictionary implementations in C, I would be very interested in seeing your implementation that fits in two dozen lines of code.

	
ddevault on Jan 27, 2021 | root | parent | next [–]

Threw together an example (untested, with obvious errors) to give you an idea of what it could look like:
https://paste.sr.ht/~sircmpwn/3122d4a27a8e5312462e2329bf7ed6...

Actually managed to get it to exactly 2 dozen lines of code, not including the header, which isn't bad for an off-the-cuff remark.

You'd naturally expand or shrink this with whatever subset of map functions you require, like key/value enumeration, object deletion, resizing, whatever. It depends on your use-case. I don't believe in generic code.


	
saagarjha on Jan 27, 2021 | root | parent | next [–]

Ok, that makes more sense. I was considering a slightly more fully-featured table and including the header (see: https://gist.github.com/saagarjha/00faa1963023206a8ccd987798...) and I was a couple times larger than your number, so I was trying to figure out what you were doing that I was unable to replicate…

	
vitno on Jan 27, 2021 | root | parent | prev | next [–]

that's not true these days, rustls is a great TLS lib that has been through at least one serious external security audit.
https://cure53.de/pentest-report_rustls.pdf


	
roblabla on Jan 27, 2021 | root | parent | next [–]

For what it's worth, rustls relies on ring which has primitives written in C and ASM because getting constant-time operation guarantees from Rust is Very Hard. Though progress is being made on this area.

	
vitno on Jan 26, 2021 | root | parent | prev | next [–]

Except that Rust is also a much much more expressive language. Even ignoring things like solid module support and libraries you'll find your Rust programs to be much fewer LoC (assuming bug/LoC is the right metric) for equivalent functionality.
I agree that rewrites have the serious potential to introduce new bugs and the cost is rarely worth it if the codebase is actually that stable and low througput, but the reality is that most aren't. A one time high cost in exchange for introducing 70% less bugs over a period of N years starts to look like a good trade off.

Yes, complexity is the root of all evil. I can get onboard with the whole statement except the "no matter what language you use". If you have the ability to use any language that enforces memory safety, we should use it.


	
ddevault on Jan 26, 2021 | root | parent | next [–]

Lines of code is a poor approximation for complexity. Rust programs are shorter, but they are not less complex. The AST is similar and the graph of relationships between different parts of the code is much more complex than in C. Overall I'd say it balances at best, if not that Rust is more complex.

	
roca on Jan 27, 2021 | root | parent | next [–]

The sudo code in question is typical C: string processing with pointers and hand-rolled byte manipulation, size calculations, manual buffer allocation and freeing, and so on. The Rust equivalents of all this are far simpler.

	
swsieber on Jan 27, 2021 | root | parent | prev | next [–]

Lines of code is great approximation for complexity, or at least how many bugs you're writing: https://softwareengineering.stackexchange.com/questions/1856...

	
ddevault on Jan 27, 2021 | root | parent | next [–]

Perhaps indeed! But a crucial distinction is that I consider the complexity in the langauge, compiler, and standard library to all be influences on your program's total complexity as well. Using std::List (or whatever you call it) has the same total complexity as writing your own little growable array.

	
roca on Jan 27, 2021 | root | parent | next [–]

From the point of view of bugginess, complexity in the implementations of massively popular libraries is far less of an issue than code you just wrote yourself, because the code in those libraries will have received much more testing than the code you just wrote yourself. So it doesn't really make sense to just add the complexity of components up like that.

	
joveian on Jan 27, 2021 | root | parent | next [–]

sudo is quite a popular utility, by the same logic it might be expected to be well tested...

	
swsieber on Jan 27, 2021 | root | parent | next [–]

Yes. And I shudder to think just how many bugs there would be in a home-grown sudo replacement.

	
jodrellblank on Jan 27, 2021 | root | parent | prev | next [–]

> "Even if we run the same math with 7 out of 10 bugs being memory safety related, and assuming that Rust prevents all of them, those same example programs end up with 30 bugs in Rust and 10 bugs in C."
Maybe but not necessarily; it's reasonable to assume that Microsoft and FaceBook put non-zero effort into designing around, programming around, testing, looking for and fixing memory safety related issues in their C code. It could be the case that not having to care so much about those frees up some non-trivial amount of attention and time which could be spent on the other classes of problems.


	
joveian on Jan 27, 2021 | root | parent | next [–]

Similarly, it is possible that they would use the time to add new features with new bugs. I'd personally suspect that to be the more common outcome.

	
jodrellblank on Jan 27, 2021 | parent | prev | next [–]

> "Furthermore, rewriting an established program from one language to another will always introduce more bugs than it fixes"
Here[1] is a link to a slideshow of a talk on the F# language, with a case study from EON PowerGen company rewriting the core of an application evaluating revenue due from their balancing services contracts nationwide in the UK. It was originally 350,000 lines of C# developed by 8 people in 5 years and incomplete. It was redeveloped by 3 people (2 had never used F# before) in 30,000 lines, complete in 1 year.

They claim zero bugs in the F# redeveloped system (page 29). This example also gets a mention in a Don Syme (F# language designer) talk in 2018[2] with the PowerGen employee in the audience.

The PDF cites a testimonial from Kaggle saying they're moving more and more of their application into F# which is "shorter, easier to read, easier to refactor, and because of strong typing, contains far fewer bugs".

[1] https://www.microsoft.com/en-us/research/wp-content/uploads/...

[2] https://www.youtube.com/watch?v=kU13g_noAQM


	
comex on Jan 26, 2021 | parent | prev | next [–]

Incidentally, after inspecting doas for a few minutes, I found two near-vulnerability bugs in it.
The first bug lets any user cause doas to read out of bounds of an array, though not in a way that's exploitable.

Well, it's arguably a bug in libc. If you run doas with a completely empty argv (argc = 0, so not even an executable name; the two systems I tried, Linux and macOS, both let you do this), getopt will exit with optind = 1. Then when doas does;

    argv += optind;
    argc -= optind;
`argc` will become negative, and `argv` will advance past the null terminator. On most OSes, the `argv` array is immediately followed in memory by `environ`, so argv will now point to the list of environment variables.
doas will then dereference argv, and generally act as if you tried to execute a command consisting of the environment variables. However, the environment variables are not secret, and doas doesn't behave any differently than if you just passed the environment variables as normal command-line arguments, so this is not exploitable.

On an OS where argv is not followed by environ or a similar array of character pointers, doas might crash instead, although since it only reads from those pointers rather than writing to them, this still probably wouldn't be exploitable.

The second bug would compromise memory safety if things were slightly different. The bug is in configuration file parsing. Even if it did compromise memory safety, it would not actually be exploitable, because doas normally only parses the trusted systemwide configuration file. It can be asked to parse a configuration file passed on the command line, but it drops privileges before doing so. This is a good example of layered defense, so kudos to doas for that! Still, I thought the bug was worth mentioning.

The bug is a traditional sort of integer overflow. parse.y grows the array of rules with

    maxrules *= 2;
but maxrules is an int, so this will eventually overflow if the configuration file is large enough.
However, because maxrules happens to be signed, before doubling produces a smaller-than-expected positive value, it will first produce a negative value. This will then get sign-extended when converting to size_t (assuming 32-bit int and 64-bit size_t), and reallocarray's overflow check will trigger, causing reallocarray to return NULL. doas interprets that as out-of-memory and handles it cleanly.

(On a system where sizeof(int) == sizeof(size_t), things are a bit different, but it will just run out of memory before maxrules gets that high.)

Moral of the story? Well, as I see it:

Simplicity and layered defense, both featured in doas, are both effective ways to avoid vulnerabilities. But guaranteed memory safety, which would require a different implementation language, is also an effective way to avoid vulnerabilities. You aren't forced to pick and choose. Why not demand all three?


	
ben_bai on Jan 27, 2021 | root | parent | next [–]

The argv += optind; is a standard pattern. I have never considered argc=0 case to be possible. I need to read some more on this.
As for your second find. It already got fixed: https://marc.info/?l=openbsd-cvs&m=161176698927944&w=2


	
ddevault on Jan 26, 2021 | root | parent | prev | next [–]

Nice finds. I would agree that that's more arguably a bug in libc than in doas, but also note that the startup code for any language has to consider this case. As far as theoretical operating systems are concerned, this is a consequence of the System-V ABI, so any OS compatible with it would have the same issue.
As for the integer overflow case, it's also highly unlikely to be exploitable, even if it were unsigned - the system would have to, as I'm sure you can infer, have tens of millions of rules before this was an issue. It's quite within the realm of reason, in my opinion, to declare this an acceptable trade-off. The rest of your explanation shows that even if this weren't the case, the bug wouldn't be exploitable.

Anyway, I like your comment, but I'd recommend a different moral to this story: in the space of 47 minutes you were able to conduct a reasonably thorough audit on the doas codebase. Wanna give that a shot for sudo now?


	
comex on Jan 26, 2021 | root | parent | next [–]

> I would agree that that's more arguably a bug in libc than in doas, but also note that the startup code for any language has to consider this case.
This is true, but for a language where dynamically sized arrays are a standard data type, the most natural thing to do is to start by collecting the arguments into an array (maybe copying the strings at this point, maybe not). All further argument parsing is done with the array and is thus bounds-checked. I checked Rust's standard library and sure enough, it follows this pattern. Though, I could imagine some hypothetical startup code messing up the argc=0 case if it tried to separate argv[0] from the rest of the arguments while constructing the array.

> Anyway, I like your comment, but I'd recommend a different moral to this story: in the space of 47 minutes you were able to conduct a reasonably thorough audit on the doas codebase. Wanna give that a shot for sudo now?

Fair point. (And I didn't downvote you.) But in my opinion, that just confirms my view: ideally you want both simplicity and memory safety.


	
ddevault on Jan 26, 2021 | root | parent | next [–]

Aye, I agree. But if we consider that case, a similar mistake could be made: hard-coding argv[0]. The result is different, in that the program just aborts, but it's still the Wrong Thing To Do, and in both cases it never leads to anything exploitable. Bugs are bugs, no matter what language. We could come up with examples all day. Just head to your nearest Rust program's bug tracker :)

	
gpm on Jan 27, 2021 | root | parent | next [–]

Aborting when argv[0] doesn't exist... is a perfectly reasonable thing to do? Someone called the program with arguments severely out of spec, crashing is fine.

	
ddevault on Jan 27, 2021 | root | parent | next [–]

It's actually within spec, in this case. Still reasonable?

	
gpm on Jan 27, 2021 | root | parent | next [–]

It's within the C and systemv abi specs, but it's not within the implicit contract of how you call command line programs. I'm fine with it.

	
ddevault on Jan 27, 2021 | root | parent | next [–]

Right, but if it was within the specs, possible to craft a scenario for, and leads to a security vulnerability, then does it suddenly matter? A bug is a bug. If it doesn't matter for Rust then it doesn't matter for C.

	
gpm on Jan 27, 2021 | root | parent | next [–]

> and leads to a security vulnerability
I have trouble imagining how aborting leads to a security vulnerability? That's literally running no code, the opposite of running arbitrary code.

Aborting is fine in any language. Criticisms of C here would come about because C doesn't abort when it should (null pointer deref, array out of bounds, etc), not the inverse.


	
staticassertion on Jan 26, 2021 | parent | prev | next [–]

A lot of your statements are pretty strong, and imo totally incorrect.
> Complexity breeds bugs, including security bugs, and memory safety doesn't change that.

Yes, memory safety changes that radically.

> A simpler program will generally be more secure than a complicated one, no matter what language either is written in.

Disagree, but the statement is really weak anyways, especially since 'complexity' is an ill-defined term. More features? Cyclomatic?

> urthermore, rewriting an established program from one language to another will always introduce more bugs than it fixes, and more severely the more complex the program is.

Should be obvious to anyone that this isn't true.

> The single best way to improve security is to reduce the attack surface,

Not true, but it's a great way to start.


	
ddevault on Jan 26, 2021 | root | parent | next [–]

>Disagree, but the statement is really weak anyways, especially since 'complexity' is an ill-defined term. More features? Cyclomatic?
I'm not sure of any definition of complexity you could appeal to which makes my argument weak.

>>rewriting an established program from one language to another will always introduce more bugs than it fixes, and more severely the more complex the program is.

>Should be obvious to anyone that this isn't true.

The opposite is painfully obvious: (1) Writing code causes bugs. (2) Rewriting an established project involves writing more code than leaving it would. (3) Writing all of that new code will introduce new bugs which were not present in the original.


	
staticassertion on Jan 27, 2021 | root | parent | next [–]

Yeah I think that's an absurd reduction. Rewriting code means that you can solve fundamental architectural issues, that you can start fresh with better tooling, that you have the lessons learned without the technical debt, etc.

	
ddevault on Jan 27, 2021 | root | parent | next [–]

Yeah, but why the assumption that those things are an issue? We're talking about mature codebases. Rewriting it again in C would also give you a chance to start fresh with better tooling, lessons learned, paying back tech debt, etc. Even still, you're going to introduce new bugs in the process. You might fix a few hard-to-address architectural issues, but all of the other bugs would be easier to fix in the original codebase than by rewriting the whole thing.
I'm not saying that a rewrite is never justified, but rather that the argument that we should rewrite in Rust simply to avoid bugs has little weight.


	
gameswithgo on Jan 27, 2021 | prev [–]

Rust would have prevented the -1 as a UUID too, because you would have used a sum type (Rust enums) instead of a sigil there. Its easier, its idiomatic, its more clear, and the compiler knows how to optimize the overhead away a lot of the time.

	
comex on Jan 27, 2021 | parent | next [–]

Well, in this particular case, the special behavior of -1 is baked into the setresuid system call, while sudo thought it was just an ordinary UID. So if you look at one of the Rust operating system projects designed from scratch from-scratch OS designs, it might not have this kind of pitfall. But if you literally just reimplement sudo for existing OSes in Rust – which I think would be a neat project for someone to take on – you’d be at risk of running into it.

	
j16sdiz on Jan 27, 2021 | parent | prev [–]

It is a uid (as in user id), not uuid. Don’t think you can use sum type for that

	
steveklabnik on Jan 27, 2021 | root | parent [–]

It is a user id, but that bug happened because a -1 was being returned as an error code in one place, and then being accidentally passed in another place. The sum type would be used as the “this possibly errors” return type in the first function, making the bug effectively impossible to happen by accident.

