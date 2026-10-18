
How to Write a New Osquery Table

##
#
https://www.kolide.com/blog/how-to-write-a-new-osquery-table
#
##

Jason Meller
Introduction

One of my favorite features of osquery is the delightful user experience associated with developing new virtual tables. 
In this guide, we will work together to implement a new high-value table from scratch that currently doesn’t exist in osquery. 
Specifically, we will implement a bluetooth table that works on macOS.

We’ll first review table design theory, including what makes a good table great and how to balance user privacy concerns with the value needed by the security team. After a bit of theory, we’ll set up an osquery development environment and code our table in Objective-C++. Finally, after some testing, we’ll walk through preparing a pull request for submission to the osquery project.

My goal is that after reading this guide, you will be inspired and empowered to contribute new tables to the osquery ecosystem. Barring that excellent outcome, you should at the very least walk away with a much greater appreciation for the process.
What is osquery?

Osquery is a performant, open-source, multi-platform host agent created at Facebook. It allows you to query details about the systems in your fleet as if they were in a relational SQL database. Osquery comes bundled with hundreds of tables covering everything from running processes, to details on nearby WiFi networks, to loaded kernel extensions. While these included tables cover most use-cases, many important tables have yet to be written. Since osquery is 100% free and open-source software, instead of waiting for a commercial vendor to support a new operating system version or feature, anyone motivated can fill these gaps and contribute their own tables and features.
My qualifications

Over the years, I have contributed eight full tables to the osquery agent:

    gatekeeper & gatekeeper_approved_apps (Github PR)
    sharing_preferences (Github PR)
    shared_folders (Github PR)
    battery (Github PR)
    screenlock (Github PR | Blog Post)
    windows_security_center (Github PR)
    location_services (Github PR)

In this guide, we will contribute a brand new table that doesn’t currently exist in osquery. In fact, we will stop short of actually contributing to the project. This will ensure future folks who find this article can enjoy the feeling of adding something new to the project on their local machine.

While the novelty of the code we are writing is a good lure to get you to try this out, even without that, I sincerely hope that this guide demystifies the process to help you feel contributing a table is within your reach.
You don’t have to be a C++ expert

C, C++, and Objective-C are the primary languages we use to write virtual tables in osquery. For many folks who are only familiar with more modern compiled languages like Golang, Swift, or Rust, this can feel like a non-starter.

But I don’t think it should be.

Before my first contribution, I hadn’t written a lick of production code in any of those languages. My only exposure was briefly in college in an introduction to computer science class, and it was very superficial. Even today, if you pressed me to write an iPhone app in Objective-C, I would have to look up introductory courses online. It’s not happening.

Even with this limited skill-set, I was shocked at how easy it was for me to get started. My first contribution took me less time than writing this guide!

It turns out I got very lucky. Writing osquery tables is perhaps one of the best ways to be introduced to C, C++, Objective-C, and their association build tooling. If these are languages you are interested in learning, you’ll find the osquery project to be the perfect proving ground to hone your skills.

Thanks to osquery’s superb documentation and well-reasoned code organization, getting a productive working development environment up and running is a snap.
Prerequisites

While I tried to make this guide as accessible as possible, there are a few things you should know before we get started:

    A working knowledge of osquery, relational databases, and SQL.

    You don’t need a lot of C++ or Objective-C experience, but some brief exposure will help. Understanding data types and how to call classes and methods in Objective-C will make the example code a bit easier to read. Also, you should have a basic knowledge of coding (variables, loops, conditionals, etc.). I come from a Ruby/Python background, if that tells you anything.

    How to use git and the Github pull request process.

    Basic familiarity working with the terminal.

    A text editor suitable for writing code. I use Microsoft’s Visual Studio Code.

Don’t worry if you have only a tenuous grasp of some of the concepts above. I’ll be going through the technical areas step-by-step.
Why You Should Write an Osquery Table

At this point in the post, you might be thinking to yourself, “Even if it’s as easy as you claim, why should I spend valuable time and effort writing my own osquery table?”

I don’t blame anyone who has this perspective. One of the significant advantages of using osquery is enjoying the benefits of the hard work previous developers put into the tool and not have to suffer as you try to source the data yourself.

Even though that is true, I have a pitch for you. And no, it’s not an appeal to “give back to the community.” Forget the community. Write an osquery table for yourself. It may sound like a selfish attitude, but even if you are building osquery tables to benefit your organization or individual needs, it likely won’t be time wasted.

In my experience, building an osquery table yourself has the following advantages:

    Even when accounting for lack of experience, building a table yourself is the fastest way for your new table to ship in a stable release of osquery. While the development community members build requested tables all the time, it’s unlikely they will do it on your preferred timeline.

    You will increase your understanding of that operating system concept by building a table. This will not only make you a more informed person about how operating systems work, but you will also be able to use your table (and likely other tables) with more precision and produce actionable results. For the tables I wrote, I definitely have a lot of tips and tricks for querying them effectively.

    When you build a table, you are likely building it to solve real use-cases for you or your organization. If someone else builds the table for you, they may exclude a critical column or piece of data you need to make the data actionable. The adage, “if you want something done right, do it yourself,” absolutely applies.

    Thousands of people will shower you with adoration. Your name will be forever etched in the slate of computing history as a titan of the security industry

…well, maybe not that last one, but still, there is a lot in it for you and not a lot to lose except a few hours of your time. Even during the rare instances I was writing a table and bit off more than I could chew, I had enough of the leg-work done to motivate much more experienced engineers to help me get the job done.

Now that you are sufficiently convinced, it’s time to get down to brass tacks and create our table. Before we write any code, we need to think about our new table, which leads us to our first step in this process.
Step 1: Choosing the Table to Write

The hardest part of contributing a new osquery table is picking a table that will be a net-positive addition to the project. Just because a new table returns correct data doesn’t mean that it should be merged with the upstream osquery project.
Myth: If a table can be written, it should be written

A common myth is that new tables are “free” since they introduce a brand-new concept without disrupting the existing osquery table ecosystem. Nothing could be further from the truth. New tables not only increase the size of the osquery binary itself, but they also increase osquery’s complexity, the compile-time, length of the documentation, attack surface, and increase the chances of memory leaks and instability.

Even if a table is written perfectly, it must be aggressively maintained through every supported OS version once accepted. Deleting or changing the schema of a table is very challenging once users of osquery rely on its existence. We have to get as much as we can right on the first try.

With these considerations in mind, tables should always solve a real need, not add to the cacophony of irrelevant data that many security, IT, and operations professionals must comb through daily.
Where to talk about your table before you write it

If you want to talk through a table idea before you commit to writing it, one of these three options works best:

    Solicit opinions from experts in the official osquery Slack. The people there are very welcoming and friendly. Each platform has its specific channel where IT and security admins often lurk who can provide input.

    Open a Blueprint issue in the repo, and folks will comment there.

    Come to osquery’s office hours and discuss the idea directly with the technical steering committee. Office hours are held every other week and announced in the official osquery Slack within the #officehours channel.

What makes a good table?

Before writing a new table, I first pause and consider if the table will exhibit the following properties:

    High-Value  -  Can I think of at least one high-value use-case/query made possible by this table? Is that use-case only valuable to my organization, or will others benefit? (If it only helps you, consider making your new table an extension).

    Accurate -  Do you expect the data to be accurate enough for a user to draw actionable insights and conclusions?

    Future Proofed -  Does this table represent an OS concept that will stay relevant for at least two years?

    Considerate of Privacy - If this table reduces user privacy, do these high-value use-cases offset the privacy concerns?

A quick note about user privacy

Facebook created the osquery agent to gain visibility and insight into their systems, not the people behind them. That’s a crucial distinction.

Newcomers to osquery often ask why browser_history isn’t a table. The simple answer is that for most ethical organizations, the privacy implications of such a table vastly outweigh any benefits of having visibility. These people are often quick to point out several tables and features that allow, with some effort, access to personal data. This, to me, is a logical fallacy. There is a big difference between a generic utility table used with bad intentions and a purpose-built table like browser_history. The latter would guarantee a privacy violation and provide a de facto endorsement of this violation.

Organizations who legitimately need features like these are welcome to implement this functionality in an osquery extension. But for the rest of us, they reduce osquery’s credibility and add unnecessary political friction to the deployment process. Therefore, they do not belong in the default project.

If you are curious about balancing end-user privacy with security, detection, and compliance goals, I recommend reading the Honest Security Guide.
Our new table — bluetooth info

In this tutorial, we will create a table related to gathering the details about the Bluetooth support on macOS. For this new table, our motivation is to provide a way for a Mac administrator to query the state of the Bluetooth radio.

After doing a quick Google search and asking around, it seems most administrators query this information by running system_profiler SPBluetoothDataType, which produces the following (abridged) output:

Bluetooth:
```
      Bluetooth Controller:
          Address: BC:D0:74:48:DD:2D
          State: On
          Chipset: BCM_4387
          Discoverable: Off
          Firmware Version: v424
          Product ID: 0x0001
          Supported services: 0x382039 < HFP AVRCP A2DP HID Braille AACP GATT Serial >
          Transport: PCIe
          Vendor ID: 0x004C (Apple)
      Paired Bluetooth Devices:
          HomePod:
              Address: D0:81:7A:E2:87:4C
          Living Room:
              Address: DC:56:E7:3F:21:F8
          iPad:
              Address: EC:2C:E2:BA:3A:07
```
So let’s follow the first step: working through the checklist.
Is It High-Value?

Over the years, Bluetooth has developed a bad reputation for being a viable vector for remote attackers to gain unauthorized access to otherwise secured systems. The first time I went to Blackhat in 2010, several nasty attacks were circulating, and I was only allowed to go if I ensured my laptop and phone had Bluetooth fully disabled. Over a decade later, not much has changed.

In specific secure working environments, ensuring the Bluetooth radio is off unless it is absolutely needed is a best practice. Having a high-confidence report enumerates when the feature is off would be useful to security practitioners and Mac admins alike.

On the opposite end, IT admins may want to know the status of Bluetooth to troubleshoot a user that is having trouble with Airdrop, their Magic Keyboard, or headphones. As for enumeration of the connected devices, that might be helpful for IT admins to get an accurate inventory of peripherals that the device utilizes and potentially for troubleshooting.
Is it accurate?

Unless we can entirely rely on the output of this data, the table is not worth writing. Luckily, as we saw earlier, there is already a command-line application that returns a set of seemingly accurate data. Further, searching on Apple’s developer docs reveals two Apple Frameworks that we might be able to use to verify the data is accurate, specifically, CoreBluetooth and IOBluetooth.
Is it considerate of privacy?

Bluetooth is also now controversial for enabling apps to track users’ location. This has become such a problem that Apple has begun showing prompts on iOS and iPadOS that allow users to allow or deny access to the Bluetooth radio on an app-by-app basis.

Unfortunately, the Mac doesn’t have similar privacy protections. It’s therefore helpful to detect if Bluetooth is enabled so users can be advised in a product like Kolide to turn it off.

In that same vein, earlier, we also toyed with the idea of enumerating the connected devices ourselves; however, for the same reasons, we should avoid enumerating these connected devices. The use-case above around gathering device peripheral inventory is just not valuable enough to warrant the privacy violation. So we are going only to implement the Bluetooth status portion. If someone needs this feature, they should build an osquery extension.
Is t future proofed?

Apple relies more and more on Bluetooth for its wireless products. It’s likely to be a relevant technology for many years. It also seems logical to assume apps will always be able to enumerate the state of the Bluetooth radio at least, so they can present an alternative user experience if Bluetooth is not available.

Based on the above, I think our table deserves to be made (the maintainers will ultimately decide during the review process). We also decided on a major caveat that we will not enumerate connected devices for privacy reasons.

Now that we feel confident this will add value, it is time to start thinking carefully about how to design and ultimately develop our table.
Step 2: Designing Your Table

A lot of osquery tables are good, but some are great. What is the difference between good and great tables? While it’s just my opinion, I think that a good table should try to achieve all of the following:

    A great name — The table’s name should help facilitate user discovery. The primary way osquery users find tables is by perusing the schema. Unless you plan on making the table multi-platform in the future, care should be taken to pick a name that best represents that concept on the targeted platform (ex: on macOS apps is a better platform-specific term than programs)

    A use-case-driven schema — A table’s columns should be chosen to enable practical use-cases. Even when developing a platform-specific table, one should choose column names that are still valid if the table eventually works across platforms. If a table enumerates data that can be different per user, include a username or UID column for easier joining.

    Accurate data — Data should be procured from accurate sources and normalized to standard units (ex: timestamps are always UNIX epoch). In non-privileged environments, a good table returns as much data as practically possible.

    Complete documentation — Great table documentation should include relevant examples and descriptions that help users interpret numerical codes and other data that aren’t obvious at face value. If a user can’t understand the output of the table, then it doesn’t do them much good.

    Performant  -  When queried naively (ex: SELECT * FROM table), the table should return results with the lowest performance overhead possible. If specific columns are computationally expensive, they should be excluded by default unless the user queries explicitly for them.

A quick word about tables names that end in “events”

Don’t end your table name with the word events unless you know what you are doing. In osquery tables like process_events, disk_events, and file_events behave differently than standard tables. As their name implies, they produce logs of events that have happened since the last time the table was queried, not system’s current state. You can read more here.
Step 3: Strategizing Development

The paradoxical secret of new table development is that it’s all been done before. What I mean is, while the table itself may be new and innovative, the underlying strategies it uses to collect the data necessary to populate the table are likely not.

For all of the macOS tables I’ve developed, the data is sourced by implementing one of the following simple strategies:

    Reading a .plist —  macOS stores and continuously updates a surprisingly amount of valuable data in plists (dictionaries of properties) littered throughout the operating system. I’ve used this strategy in many of the macOS tables I wrote, including gatekeeper, portions of sharing_preferences, and some of the columns in the apps table.

    Reading an SQLite database file  —  When plists aren’t enough, macOS often uses SQLite database files to store logs and other structured data on the file system. I used this strategy when writing the gatekeeper_approved_apps and tables. If all the data you need is in an SQLite database, you may not need to write a full-fledged table and instead can do what’s known as Automatic Table Configuration (ATC).

    Using a macOS API — Apple’s APIs are surprisingly well documented, and many command-line utilities leverage these APIs to produce their output. For example, the shared_folders table leverages the public Directory Services API to output all files and folders that a computer has shared on the network. This is the best-case scenario because these public APIs come with some guarantees to developers, ensuring their viability in future versions of macOS are released. This means our table will likely not break when new macOS versions are released. On the opposite end of the spectrum, sometimes Apple’s tools will use private APIs that don’t carry such a contract and should be used only as a last resort (I ran into this for several fields in the sharing_preferences table).

What about shelling out to a binary?

Sometimes when a user of osquery is advocating for a new table, they point to a command-line tool that produces the exact output they are looking for (in our case, system_profiler SPBluetoothDataType does the job). These users might expect the table to be easily developed by quickly asking the osquery process to execute the command-line tool, read its output, and produce a table.

This practice, casually called “shelling out,” is an anti-pattern in the osquery codebase, and any contributions that shell out will not be acceptable.

While shelling out often results in a table that can be developed quickly, it comes with many nefarious side-effects and disadvantages:

    Performance can be poor and unreliable when shelling out to external tools; it’s often orders of magnitude faster to use the API the tool uses to produce the same output.

    The table will stop working if the tool is renamed, removed from your $PATH, deleted, or changed.

    Command-line tools can change all the time (renamed command-line arguments, differences in output formatting), which can break a table unexpectedly. These can produce errors nearly impossible to debug.

While some of these disadvantages can be realized even when developing tables the right way, they occur less frequently, and the extra development time is well-worth reducing the likelihood our table will be slow or break unexpectedly.

Sometimes, shelling out is the only way to get the data you need in a modern world with protected APIs and entitlements. If this is the case, building an osquery extension that shells out or contributing to something like Kolide’s Launcher project are both great options.

Back to our Bluetooth information table, after doing some Googling, I found a command-line tool on Github called blueutil that produces the information we want. It does this by interacting with a public API called IOBluetooth. If we look at the source code, we see something like the following:

// private methods
int IOBluetoothPreferencesAvailable();
int IOBluetoothPreferenceGetControllerPowerState();
int IOBluetoothPreferenceGetDiscoverableState();

This implies that we need to use a few private methods that exist in the library to get the data we want but are not explicitly defined in the header file.

One thing that caught my eye here was this IOBluetoothPreferenceGetDiscoverableState. When we enumerated the Bluetooth information using system_profiler SPBluetoothDataType, it included: “Discoverable: On.” But running this third-party blueutil CLI app, I get a different set of data…

$ blueutil
Power: 1
Discoverable: 0

There is an issue open for this in the blutil repo.

    Just tested the discoverability […] To me, it seems that opening the pref pane always overrules the setting. And is not reported in the IOBluetoothPreferenceGetDiscoverableState however, the System Report does show the setting and is updated when opening the pref pane…

This is not good. Even though this tool uses a private method for obtaining the status of the Bluetooth devices, it’s not showing an important piece of data accurately. It also calls into question the accuracy of other data in this API. This API has already had one strike against it, and this isn’t baseball.

In fact, in my testing of the original CLI command, we found that system_profiler SPBluetoothDataType seems to be the only CLI tool that accurately reports on discoverability. We should do our best to emulate the method it’s using.

Remember, the goal is to become familiar with the data before writing our table. Suppose we, the table’s authors, don’t understand the underlying Operating System concepts the table is trying to convey. In that case, we have little hope of producing a table that considers the nuances and variability in the data.
A quick note on using Objective-C

You may have noticed we are quickly going down a rabbit hole that will require us to write Objective-C, not C++ (the language used to write most osquery tables). Fortunately for us, the osquery core team has created a build environment where you can intermingle both Objective-C and C++ code within the same file. We won’t get into the dark compiler magic that makes it possible. Instead, we can appreciate all the hard work done for us to use as little Objective-C as possible to call these APIs, and we can use the much easier to understand (in my opinion) C++ syntax and libraries for everything else.

Now that we know what information we can obtain from this API, let’s design our Bluetooth info table. After looking at various docs and the output of system_profiler, I think our table should look like the following:
Table name - bluetooth_info

    state - One of the following: 1 (for “On”) or 0 (for “Off”)

    discoverable - One of the following: 1 (for “On”) or 0 (for “Off”)

    address - The MAC address of the Bluetooth radio (colon-delimited hexadecimal)

    vendor_id - A hexadecimal number representing the Bluetooth Radio vendors manufacturing ID

    chipset - Text representing the underlying chipset used by the Bluetooth radio.

    firmware_version - Text representing the currently loaded firmware on the Bluetooth radio.

    supported_services - A comma-separated list of Bluetooth Supported services and profiles

Notice I haven’t written code. I am just writing notes to myself I can use to start quickly developing my table. These notes will directly translate to our table specification.

When designing the schema, it becomes apparent that this table should only produce a single row describing the internal Bluetooth radio that ships with a Mac. While we could design the table to enumerate all Bluetooth devices, in my mind, this would muddy our proposed use-cases and therefore makes our decision to limit the scope of this table relatively easy to accept.
Starting development and next steps

After all that discussion and design, we will finally move away from the conceptual and academic and get our hands dirty while facing the harsh (but sometimes enjoyable) realities of writing system software.
Step 4: Setting Up Our Osquery Development Environment

If you are like me and had the misfortune of spending hours or even days trying to set up poorly thought out C projects to contribute a small one-line fix, osquery will seem like a breath of fresh air.

The team has put in a lot of effort to make this process ridiculously painless with great automated tooling and concise yet accurate documentation.

Instead of rehashing the already well-written docs, I encourage you to follow them and come back when you are ready.

If you just want the tl;dr and happen to be running macOS, here is the short version:

# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install prerequisites
xcode-select --install
brew install ccache git git-lfs cmake python clang-format flex bison

# Optional: install python tests prerequisites
pip3 install --user setuptools pexpect==3.3 psutil timeout_decorator six thrift==0.11.0 osquery

# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Configure build to target earliest supported version of macOS
mkdir build; cd build
cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 -DOSQUERY_BUILD_TESTS=ON ..

# Build
cmake --build . -j $(sysctl -n hw.ncpu)

The first build process will take a while (for me, it takes almost 15 minutes on a 2021 Macbook Pro with an M1 Pro) and may produce many warnings that you can safely ignore. If all goes well in the end, you’ll see something like:

[100%] Linking CXX static library libosquery_main.a
[100%] Built target osquery_main
[100%] Generating empty_osqueryd_target_source_file.cpp
[100%] Building CXX object osquery/CMakeFiles/osqueryd.dir/empty_osqueryd_target_source_file.cpp.o
[100%] Linking CXX executable osqueryd
[100%] Built target osqueryd
[100%] Generating osqueryi
[100%] Built target create_osqueryi

Once completed, we will want to verify that osquery works. Since osqueryi is easier for us to test, simply run ./osquery/osqueryi and try running a query like SELECT version FROM osquery_info;. You will see the version number and the most recent commit SHA1 hash you compiled against if it’s working

osquery> select version from osquery_info;
+---------------------+
| version             |
+---------------------+
| 5.2.2-23-gda909acb8 |
+---------------------+

If things didn’t work out after following the steps above, I suggest you read the official documentation first. If you are still stuck, don’t despair! You can join the osquery slack and get help right away.
Step 5: Create a Table Specification

Now that we’ve got our development environment up and running, it is time for us to take our first steps towards writing our table, the table specification. The table specification files are located in the specs folder. Platform-specific specs live in a child directory labeled with their respective platform. Here is an example of the spec for the nvram table.

table_name("nvram")
description("Apple NVRAM variable listing.")
schema([
    Column("name", TEXT, "Variable name"),
    Column("type", TEXT, "Data type (CFData, CFString, etc)"),
    Column("value", TEXT, "Raw variable data"),
])
implementation("nvram@genNVRAM")

While technically written in Python, these specification files are a custom DSL (a domain-specific language) that describes a table and its associated schema. These files are important not only because they contain the structure of your table, but they also tell the compiler where to find the code that produces the data for the table. Not only that, these files power the documentation on the osquery.io website!

My recommendation when writing a spec is to copy an existing spec and replace the column names, data types, and descriptions with the correct information. Don’t worry about getting it perfect on the first try. As we play with the actual data coming from real systems, we are likely to change the spec file as our understanding of the underlying concept of Bluetooth information improves.

# osquery/tables/system/darwin/bluetooth_info.table

table_name("bluetooth_info")
description("Provides information about the internal bluetooth radio of a Mac.")
schema([
    Column("state", INTEGER, "1 if Bluetooth is enabled. Otherwise 0"),
    Column("discoverable", INTEGER, "1 if The Bluetooth radio is in discovery mode and advertising itself to other devices. Otherwise 0."),
    Column("address", TEXT, "The MAC address of the Bluetooth radio in colon delimited hexadecimal"),
    Column("vendor_id", TEXT, "A hexadecimal number representing the Bluetooth Radio vendors' manufacturing ID. Ref: http://domoticx.com/bluetooth-company-identifiers/"),
    Column("chipset", TEXT, "Text representing the underlying chipset used by the Bluetooth radio."),
    Column("firmware_version", TEXT, "Text representing the currently loaded firmware on the Bluetooth radio."),
    Column("supported_services", TEXT, "A comma separated list of codes and strings representing supported Bluetooth services and profiles. Ref: https://en.wikipedia.org/wiki/List_of_Bluetooth_profiles"),
])
implementation("bluetooth_info@genBluetoothInfo")

There are a few things I want to call out in these specs.

First, the concept of column data types (the things that say TEXT, INTEGER, DOUBLE, etc.) These types help users who will be querying this table know what type of data to expect (printed text, numbers, numbers with decimals, true or false values, etc.). SQLite, the engine osquery uses to make virtual tables, translates these types into affinities (the internal structures used to store this data). For most tables, you don’t need to know more than the four basic types mentioned above, but if you are curious, you can read more about types and affinities in the SQLite documentation and learn some interesting tidbits. For example, did you know SQLite has no concept of a boolean (true/false)? This is why we use INTEGER in our specs above with additional documentation to simulate that datatype.

The second thing I want to discuss is the implementation statement. This statement describes the compiler’s function to produce data that powers this table. It’s essential to name the functions as uniquely and descriptively as possible. These names must be unique across all table implementation source-code files, and naming them generically could cause you or another developer in the future a duplicate symbol for architecture error.
Step 6: Write a Placeholder Table Implementation

Now that we’ve written our specification, we need to write the implementation source file. Let’s start by making a bare-bones implementation that will output something when we query our table.
The implementation file

First, let’s create a blank file called bluetooth_info.mm in the osquery/tables/system/darwin folder. Earlier, we learned we need to query an Apple API to get this Bluetooth information, using a little Objective-C. By giving our file the extension .mm, we tell the compiler that some Objective-C++ code lives here. Objective-C++ is amazing because it allows us to write both native Objective-C (interfacing with Apple’s APIs) and mix that with the much more developer-friendly C++.

In our blank, file let’s start with the following basic structure:

// osquery/tables/system/darwin/bluetooth_info.mm

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

QueryData genBluetoothInfo(QueryContext &context) {
  QueryData results;
  Row r;
  r["state"] = INTEGER(1);
  r["discoverable"] = INTEGER(0);
  r["chipset"] = TEXT("THX-1138");
  results.push_back(r);
  return results;
}


} // namespace tables
} // namespace osquery

While you may not understand everything, there is a lot here that we can understand. Here are the two most important ones:

    We’ve defined a function that matches the implementation section in our tables’ specification file. This function accepts a context argument and returns typed objects that osquery knows how to convert into SQL results.

    We can set a column’s information using the following syntax r["column_name"] = TYPE(value);

    We are only returning one row of information in this table, so we can populate the row and push it into the results QueryData object all at once. If we wanted to return many rows, we would loop through a list of stuff and then push each row individually to the result set at the end of the loop.

    We didn’t have to return all the columns (we are missing quite a few in this primitive implementation)

    Most importantly, look at all the code we’re not writing! We need to know nothing about the underlying SQL subsystem essentially. Osquery just handles this for us!

How to compile our new table

Believe it or not, this code snippet will run with a bit of extra work. Don’t believe me? Let’s compile it!

Before we can do that, we need to tell cmake (the tool we used to compile osquery earlier) where to find our new table specs and implementation.

This is done in two files shown below:
osquery/specs/CMakeLists.txt

<snip...>

set(platform_dependent_spec_files
    "arp_cache.table:linux,macos,windows"
    "atom_packages.table:linux,macos,windows"
    "darwin/account_policy_data.table:macos"
    "darwin/ad_config.table:macos"
    "darwin/alf.table:macos"

<snip...>

    "darwin/authorizations.table:macos"
    "darwin/battery.table:macos"
    "darwin/bluetooth_info.table:macos"
    "darwin/browser_plugins.table:macos"

As you can see above, we have inserted the relative path to both of our table specification files in alphabetical order under the platform_dependent_spec_files set. Each entry in this set contains the file, a : as a delimiter and then a comma-separated list of valid platforms.
osquery/tables/system/CMakeLists.txt

<snip...>

elseif(DEFINED PLATFORM_MACOS)
  list(APPEND source_files
    darwin/account_policy_data.mm
    darwin/acpi_tables.cpp
    darwin/ad_config.cpp
    darwin/apps.mm

<snip...>

      darwin/battery.mm
      darwin/block_devices.cpp
      darwin/bluetooth_info.mm
      darwin/certificates.mm

Just like before, we have inserted the relative path to our implementation file in alphabetical order in the section under DEFINED PLATFORM_MACOS. This tells the compiler to include and link these source code files if the compilation target matches the PLATFORM_MACOS constant.

With that part complete, all we need to do is rerun our cmake command from earlier…

# Make sure you are still in the ./build folder
cmake --build . -j $(sysctl -n hw.ncpu)

Once your compilation completes, execute osqueryi and try the following query:

SELECT * FROM bluetooth_info;

+-------+--------------+---------+-----------+----------+------------------+--------------------+
| state | discoverable | address | vendor_id | chipset  | firmware_version | supported_services |
+-------+--------------+---------+-----------+----------+------------------+--------------------+
| 1     | 0            |         |           | THX-1138 |                  |                    |
+-------+--------------+---------+-----------+----------+------------------+--------------------+

With minimal effort, we have just created a table that produces results. Sadly, the results are not real, but that’s okay! Let’s start working towards our goal of getting this table to produce real outputs.
Step 7: Explore the Data with Debug Statements

Now it’s time to make the leap from fake data to starting to play with the actual OS internals that will get us what we need. This is the most challenging part of creating a new table, so we will want to get familiar with ways to quickly iterate through ideas without having the ceremony of converting data types into the final forms osquery needs to display info in the table.
Introducing NSLog

One of those ways is writing debug statements you can read in the console. Since this is a macOS table, we will likley be dealing with NextStep (NS) and other Objective-C data types like NSDictionary NSArray, BOOL, etc. The class NSLog allows us to quickly output these objects in human-readable forms to determine if we’ve found a viable way of returning our data. We will use it liberally later on in this step.
How do we get data out of system profiler?

Now for the key question. We know the data we want is in System Profiler, and we know we aren’t allowed to shell out and get it. So how do we do this?

My usual first step is to take the command-line tool and throw it into a dissembler like Hopper. I like Hopper a lot because despite not knowing much about dissembling binaries or how to read raw ASM, I can generally grep around for strings that give me clues that will help me come up with more targeted Google searches. This is how we built our macOS Screenlock table.

But this time, there was no need for Hopper. With some simple Google searches, I discovered a great article by Dr. Howard Oakley of the Electric Light Company that breaks down how system_profiler works in a deep level of detail.

    system_profiler is surprisingly complex. The command tool in /usr/sbin/ turns out to be a small stub which relies on calling helper tools stored in the /System/Library/SystemProfiler folder as .spreporter bundles. Each of those contains another Mach-O executable complete with its own localised strings, and in some cases such as SPiBridgeReporter.spreporter there are also XPC services, which in turn have their localised strings

Further down, he reproduces the following console logs:

0.544816 com.apple.SPSupport Reporting system_profiler SPSupport -[SPDocument reportForDataType:] -- Dispatching helperTool request for dataType SPiBridgeDataType.

[SPDocument reportForDataType] looks like what we need. Let’s see if we can get that working.

In these cases, I like to get a simple single-file program working before I start dealing with integrating it into the osquery source. I do this because it’s usually faster, and I can further reduce my program to just the essential elements I need for testing.

Here is the simple source file that I came up with we can use as a playground to test our theory around SPDocument. Feel free to stick this file anywhere outside of the osquery codebase (we don’t submit it later on accidentally).

// bluetooth.mm

#import <Foundation/Foundation.h>
#import <AppKit/NSDocument.h>

// Define a private method for NSDocument that is not included in the
// header file.
@interface SPDocument : NSDocument {}
- (id)reportForDataType:(id)arg1;
@end

int main() {
  // Create a URL ref for the private framework we need
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
    kCFAllocatorDefault,
    CFSTR("/System/Library/PrivateFrameworks/SPSupport.framework"),
    kCFURLPOSIXPathStyle,
    true);

  // Load the framework
  CFBundleLoadExecutable(CFBundleCreate(kCFAllocatorDefault, bundle_url));

  // A metaprogramming way of typing `id = [SPDocument new]`
  id cls = NSClassFromString(@"SPDocument");
  SEL sel = @selector(new);
  id document = [cls performSelector:sel];

  // My best guess on how to use this private method
  NSDictionary* data = [document reportForDataType:@"SPBluetoothDataType"];

  // Let's see what we get
  NSLog(@"%@", data);

  return 0;
}

And we can compile it by running gcc with the appropriate flags.

gcc -framework Foundation -framework AppKit bluetooth.mm -o bluetooth

Now let’s run our newly compiled program and see what we get!

# Don't forget to mark it executable
chmod +x bluetooth

# Run it!
./bluetooth

This is what happened when I ran it on my device…

2022-03-23 14:02:47.181 bluetooth[21892:5171488] {
    "_SPCommandLineArguments" =     (
        "/usr/sbin/system_profiler",
        "-nospawn",
        "-xml",
        SPBluetoothDataType,
        "-detailLevel",
        full
    );
    "_SPCompletionInterval" = "0.02909505367279053";
    "_SPResponseTime" = "0.04006195068359375";
    "_dataType" = SPBluetoothDataType;
    "_detailLevel" = "-1";
    "_items" =     (
                {
            "controller_properties" =             {
                "controller_address" = "BC:D0:74:48:DD:2D";
                "controller_chipset" = "BCM_4387";
                "controller_discoverable" = "attrib_off";
                "controller_firmwareVersion" = v424;
                "controller_productID" = 0x0001;
                "controller_state" = "attrib_on";
                "controller_supportedServices" = "0x382039 < HFP AVRCP A2DP HID Braille AACP GATT Serial >";
                "controller_transport" = PCIe;
                "controller_vendorID" = "0x004C (Apple)";
            };
            "devices_list" = (<REDACTED FOR PRIVACY>);
        }
    );
    "_name" = SPBluetoothDataType;
    "_parentDataType" = SPHardwareDataType;
    "_properties" =     {
        "_name" =         {
            "_detailLevel" = "-1";
            "_isColumn" = YES;
            "_isOutlineColumn" = YES;
            "_order" = 0;
        };
        "controller_address" =         {
            "_detailLevel" = 0;
            "_order" = 2;
        };
        "controller_name" =         {
            "_detailLevel" = 1;
            "_order" = 1;
        };
        "controller_properties" =         {
            "_detailLevel" = "-1";
            "_order" = 1;
        };
        "controller_state" =         {
            "_detailLevel" = "-1";
            "_order" = 3;
        };
        "device_address" =         {
            "_detailLevel" = 0;
            "_order" = 1;
        };
        "device_connected" =         {
            "_detailLevel" = "-1";
            "_order" = 2;
        };
        "device_productID" =         {
            "_detailLevel" = 0;
            "_order" = 4;
        };
        "device_vendorID" =         {
            "_detailLevel" = 0;
            "_order" = 3;
        };
        "devices_list" =         {
            "_detailLevel" = "-1";
            "_order" = 100;
        };
        volumes =         {
            "_detailLevel" = 0;
        };
    };
    "_timeStamp" = "2022-03-23 18:02:47 +0000";
    "_versionInfo" =     {
        "com.apple.SystemProfiler.SPBluetoothReporter" = 1;
    };
}

Wow! First shot out right out of the box, and we got the data we needed! That is extremely promising.

Okay, I recognize we just went through a lot of new concepts here, but essentially, this code is just doing the following:

    Initializing a new instance of a class called SPDocument.
    Calling the method reportForDataType with an NString argument of SPBluetoothDataType.
    Logging the resultant Dictionary to the screen via NSLog

Because this is a private framework, we are doing the above to allow us to call the class and function in the library without explicitly linking it to the compiler (which I couldn’t get to work). We must write the definitions manually because we aren’t linking to an actual library in the compiler. We do that using objective-c syntax at the very top of the file.

Now that we know the structure of the data we are dealing with can alter the last time just to enumerate the last entry in the NSArray that lives at the _items key. From there, we only want to grab the data in controller_properties. We can accomplish this with the following code…

    NSDictionary* report = [[document reportForDataType:@"SPBluetoothDataType"] objectForKey:@"_items"] lastObject];
    NSDictionary* data = [report objectForKey:@"controller_properties"];

Rerun it, and we should get a smaller subset of the data as shown below…

2022-03-24 09:48:45.007 bluetooth[71205:210836] {
    "controller_address" = "B8:E6:0C:2E:A4:BB";
    "controller_chipset" = "BCM_4387";
    "controller_discoverable" = "attrib_off";
    "controller_firmwareVersion" = "19.5.432.4739";
    "controller_productID" = 0x0001;
    "controller_state" = "attrib_on";
    "controller_supportedServices" = "0x382039 < HFP AVRCP A2DP HID Braille AACP GATT Serial >";
    "controller_transport" = PCIe;
    "controller_vendorID" = "0x004C (Apple)";
}

Dynamically calling a private API safely

You may be thinking, if shelling out isn’t allowed in osquery, are we allowed to use private frameworks and APIs? The answer is a resounding yes. Most information that is interesting to security and IT practitioners isn’t info that most developers need and thus never makes it into a public API. If we couldn’t use private APIs, much of the functionality that makes osquery valuable would be missing.

Even better, the way we called that private API earlier–by loading it in at run-time and calling it dynamically–is the preferred way to implement it in the osquery project. Why? It helps make osquery extremely portable.

On just Macs alone, osquery must run on a diverse set of macOS versions and architectures. If we want to link to a library or framework at compile-time, we have to be sure it will be available on every version of macOS that osquery supports. If we don’t, osquery won’t even start up!

But in our simple program above, because we are loading a library dynamically, osquery will still run even if that library doesn’t exist or is substantially different. Only our specific table will fail to run if either is the case. That’s a much better outcome!

We need to be careful, or else our table could cause osquery to segfault or even kernel panic the entire device. To be cautious, we must sanity check every step of the dynamic calling process. We also need to clean up any memory we allocate, as the garbage collector will not automatically release memory references when we load and call the library.

Given the above, let’s modify our program further to include these sanity checks. Here is the final result annotated with comments to help you understand each new change.

  // bluetooth.mm

  #import <Foundation/Foundation.h>
  #import <AppKit/NSDocument.h>

  // Define a private method for NSDocument that is not included in the
  // header file.
  @interface SPDocument : NSDocument {}
  - (id)reportForDataType:(id)arg1;
  @end

  int main() {
  // BEWARE: Because of the dynamic nature of the calls in this function, we
  // must be careful to properly clean up the memory. Any future modifications
  // to this function should attempt to ensure there are no leaks.
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/SPSupport.framework"),
      kCFURLPOSIXPathStyle,
      true);

  // Is the bundle URL itself faulty?
  if (bundle_url == nullptr) {
    NSLog(@"Error parsing SPSupport bundle URL");
    return 0;
  }

  // Is there actually a bundle at that bundle_url?
  CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFRelease(bundle_url);
  if (bundle == nullptr) {
    NSLog(@"Error opening SPSupport bundle");
    return 0;
  }

  // Ok it seems safe to load!
  CFBundleLoadExecutable(bundle);

  // The compiler will complain about memory leaks. Since we are being
  // careful we can suppress that warning with the `pragmas` below.
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Warc-performSelector-leaks"

  //
  // the rest of this is the safe equivalent of `document = [SPDocument new]`
  //

  // Does the `SPDocument` class exist?
  id cls = NSClassFromString(@"SPDocument");
  if (cls == nullptr) {
    NSLog(@"Could not load SPDocument class");
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
    return 0;
  }

  // Does the `SPDocument` does it respond to the `new` method?
  SEL sel = @selector(new);
  if (![cls respondsToSelector:sel]) {
    NSLog(@"SPDocument does not respond to new selector");
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
    return 0;
  }

  // Did calling `new` actually result in something being returned?
  id document = [cls performSelector:sel];
  if (document == nullptr) {
    NSLog(@"[SPDocument new] returned null");
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
    return 0;
  }

  // Let's undo the change to the compiler state we did earlier
  #pragma clang diagnostic pop

  // Okay let's proceed with the program as before and to remember to unload
  // the bundle and release it from memory
  NSDictionary* report = [[[document reportForDataType:@"SPBluetoothDataType"] objectForKey:@"_items"] lastObject];
  NSDictionary* data = [report objectForKey:@"controller_properties"];

  NSLog(@"%@", data);

  // Release all the objects we owned that ARC has no knowledge of so we don't
  // leak memory.
  CFRelease((__bridge CFTypeRef)document);
  CFBundleUnloadExecutable(bundle);
  CFRelease(bundle);

  return 0;
}

If you compile and rerun this, the output should not have changed, but now we have a much safer approach to loading this private framework and running the private API inside it.
Step 8: Wire It All Together

In step 7, we ended with a simple program that gives us some output we want. Let’s incorporate this code into our osquery implementation source code file and, in the process, clean it up.

Merging this code with our earlier mock table implementation (and also removing the instructive comments) gives us the following:

// osquery/tables/system/darwin/bluetooth_info.mm

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#import <Foundation/Foundation.h>
#import <AppKit/NSDocument.h>

#include <osquery/core/tables.h>

@interface SPDocument : NSDocument {}
- (id)reportForDataType:(id)arg1;
@end

namespace osquery {
namespace tables {

QueryData genBluetoothInfo(QueryContext &context) {
  Row r;
  QueryData results;

  // BEWARE: Because of the dynamic nature of the calls in this function, we
  // must be careful to properly clean up the memory. Any future modifications
  // to this function should attempt to ensure there are no leaks.
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/SPSupport.framework"),
      kCFURLPOSIXPathStyle,
      true);

  if (bundle_url == nullptr) {
    NSLog(@"Error parsing SPSupport bundle URL");
    return results;
  }

  CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFRelease(bundle_url);
  if (bundle == nullptr) {
    NSLog(@"Error opening SPSupport bundle");
    return results;
  }

  CFBundleLoadExecutable(bundle);

  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Warc-performSelector-leaks"

  id cls = NSClassFromString(@"SPDocument");
  if (cls == nullptr) {
    NSLog(@"Could not load SPDocument class");
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
    return results;
  }

  SEL sel = @selector(new);
  if (![cls respondsToSelector:sel]) {
    NSLog(@"SPDocument does not respond to new selector");
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
    return results;
  }

  id document = [cls performSelector:sel];
  if (document == nullptr) {
    NSLog(@"[SPDocument new] returned null");
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
    return results;
  }

  NSDictionary* report = [[[document reportForDataType:@"SPBluetoothDataType"] objectForKey:@"_items"] lastObject];
  NSDictionary* data = [report objectForKey:@"controller_properties"];

  #pragma clang diagnostic pop

  NSLog(@"%@", data);

  CFRelease((__bridge CFTypeRef)document);
  CFBundleUnloadExecutable(bundle);
  CFRelease(bundle);

  r["state"] = INTEGER(1);
  r["discoverable"] = INTEGER(0);
  r["chipset"] = TEXT("THX-1138");
  results.push_back(r);
  return results;
}

} // namespace tables
} // namespace osquery

The most significant material change is since now we are in a function that returns QueryData, we have to update our early returns to return results instead of 0.

We need to grab it strategically from the dictionary and put it into the final result set to get our data out.

// if the data we asked for is not populated clean up and don't proceed further
if (data == nullptr) {
  CFRelease((__bridge CFTypeRef)document);
  CFBundleUnloadExecutable(bundle);
  CFRelease(bundle);
  return results;
}

NSString* state = [data objectForKey:@"controller_state"];
NSString* discoverable = [data objectForKey:@"controller_discoverable"];
NSString* address = [data objectForKey:@"controller_address"];
NSString* chipset = [data objectForKey:@"controller_chipset"];
NSString* vendorId = [data objectForKey:@"controller_vendorID"];
NSString* firmwareVersion = [data objectForKey:@"controller_firmwareVersion"];
NSString* supportedServices = [data objectForKey:@"controller_supportedServices"];

if (state) {
  if ([state isEqualToString: @"attrib_on"]) {
    r["state"] = INTEGER(1);
  } else {
    r["state"] = INTEGER(0);
  }
}

if (discoverable) {
  if ([discoverable isEqualToString: @"attrib_on"]) {
    r["discoverable"] = INTEGER(1);
  } else {
    r["discoverable"] = INTEGER(0);
  }
}

if (address) {
  r["address"] = [address UTF8String];
}

if (chipset) {
  r["chipset"] = [chipset UTF8String];
}

if (vendorId) {
  r["vendor_id"] = [vendorId UTF8String];
}

if (firmwareVersion) {
  r["firmware_version"] = [firmwareVersion UTF8String];
}

if (supportedServices) {
  r["supported_services"] = [supportedServices UTF8String];
}

Here, we are simply pulling the values out of the dictionary and, if they exist, assigning them to the correct column. In the case of the integer style columns we created, a simple if statement with a string comparison allows us to easily convert the API’s response into the desired 0 or 1 output.

Adding this in and compiling again, I get the following output:

osquery> select * from bluetooth_info;
+-------+--------------+-------------------+----------------+----------+------------------+----------------------------------------------------------+
| state | discoverable | address           | vendor_id      | chipset  | firmware_version | supported_services                                       |
+-------+--------------+-------------------+----------------+----------+------------------+----------------------------------------------------------+
| 1     | 1            | BC:D0:74:48:DD:2D | 0x004C (Apple) | BCM_4387 | v424             | 0x382039 < HFP AVRCP A2DP HID Braille AACP GATT Serial > |
+-------+--------------+-------------------+----------------+----------+------------------+----------------------------------------------------------+

🎉🎉🎉 WE DID IT! OUR TABLE HAS REAL DATA IN IT! 🎉🎉🎉
Cleaning up

Before we move on to the testing, let’s just clean up the code slightly.

First, instead of using NSLog to return run-time errors, let’s use osquery’s built-in logging facility to return those logging messages correctly. Simple replace NSLog(@"message") with LOG(INFO) << "message". We also need to include the logger headers at the top of the file. Finally, we should also clean up any debug logs from earlier.

Beyond the logging, there is one more change we can make. It appears we are calling the same two clean-up lines when our dynamic loading dance sanity checks fail. It would be nice to distill that down to an inline function called cleanup(). We can re-define it again later as the cleanup routine adds more steps.
The final source code

Considering all of our cleanup work, we have the following final file:

// osquery/tables/system/darwin/bluetooth_info.mm

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#import <AppKit/NSDocument.h>
#import <Foundation/Foundation.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

@interface SPDocument : NSDocument {
}
- (id)reportForDataType:(id)arg1;
@end

namespace osquery {
namespace tables {

QueryData genBluetoothInfo(QueryContext& context) {
  QueryData results;
  Row r;

  // BEWARE: Because of the dynamic nature of the calls in this function, we
  // must be careful to properly clean up the memory. Any future modifications
  // to this function should attempt to ensure there are no leaks.
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/SPSupport.framework"),
      kCFURLPOSIXPathStyle,
      true);

  if (bundle_url == nullptr) {
    LOG(INFO) << "Error parsing SPSupport bundle URL";
    return results;
  }

  CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFRelease(bundle_url);
  if (bundle == nullptr) {
    LOG(INFO) << "Error opening SPSupport bundle";
    return results;
  }

  CFBundleLoadExecutable(bundle);

  std::function<void()> cleanup = [&]() {
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

  id cls = NSClassFromString(@"SPDocument");
  if (cls == nullptr) {
    LOG(INFO) << "Could not load SPDocument class";
    cleanup();

    return results;
  }

  SEL sel = @selector(new);
  if (![cls respondsToSelector:sel]) {
    LOG(INFO) << "SPDocument does not respond to new selector";
    cleanup();

    return results;
  }

  id document = [cls performSelector:sel];
  if (document == nullptr) {
    LOG(INFO) << "[SPDocument new] returned null";
    cleanup();

    return results;
  }

  #pragma clang diagnostic pop

  cleanup = [&]() {
    CFRelease((__bridge CFTypeRef)document);
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

  NSDictionary* report = [[[document reportForDataType:@"SPBluetoothDataType"]
      objectForKey:@"_items"] lastObject];
  NSDictionary* data = [report objectForKey:@"controller_properties"];

  if (data == nullptr) {
    cleanup();
    return results;
  }

  NSString* state = [data objectForKey:@"controller_state"];
  NSString* discoverable = [data objectForKey:@"controller_discoverable"];
  NSString* address = [data objectForKey:@"controller_address"];
  NSString* chipset = [data objectForKey:@"controller_chipset"];
  NSString* vendorId = [data objectForKey:@"controller_vendorID"];
  NSString* firmwareVersion = [data objectForKey:@"controller_firmwareVersion"];
  NSString* supportedServices =
      [data objectForKey:@"controller_supportedServices"];

  if (state) {
    if ([state isEqualToString:@"attrib_on"]) {
      r["state"] = INTEGER(1);
    } else {
      r["state"] = INTEGER(0);
    }
  }

  if (discoverable) {
    if ([discoverable isEqualToString:@"attrib_on"]) {
      r["discoverable"] = INTEGER(1);
    } else {
      r["discoverable"] = INTEGER(0);
    }
  }

  if (address) {
    r["address"] = [address UTF8String];
  }

  if (chipset) {
    r["chipset"] = [chipset UTF8String];
  }

  if (vendorId) {
    r["vendor_id"] = [vendorId UTF8String];
  }

  if (firmwareVersion) {
    r["firmware_version"] = [firmwareVersion UTF8String];
  }

  if (supportedServices) {
    r["supported_services"] = [supportedServices UTF8String];
  }

  cleanup();
  results.push_back(r);
  return results;
}

} // namespace tables
} // namespace osquery

Step 9: Test Your Table

“Well, it ran on my machine” is not a phrase you want to be sheepishly uttering to the osquery core team when it becomes clear the table doesn’t work across most of the millions of devices that run osquery.

To gain confidence in our table, we must test it. My approach is to do two types of testing: automated integration testing and obsessive manual verification.
Basic integration tests

Programmatically testing osquery tables is pretty tough. Most integration tests in the repo run a basic version of the query and validate the data return matches the data types you expect. The file below implements that basic testing strategy.

You will also need to add the file to tests/integration/tables/CMakeLists.txt before compilation.

// tests/integration/tables/bluetooth_info.cpp

/**
  * Copyright (c) 2014-present, The osquery authors
  *
  * This source code is licensed as defined by the LICENSE file found in the
  * root directory of this source tree.
  *
  * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
  */

 // Sanity check integration test for location_services
 // Spec file: specs/darwin/bluetooth_info.table

 #include <osquery/tests/integration/tables/helper.h>

 namespace osquery {
 namespace table_tests {

 class bluetoothInfo : public testing::Test {
  protected:
   void SetUp() override {
     setUpEnvironment();
   }
 };

 TEST_F(bluetoothInfo, test_sanity) {
   auto const data = execute_query("select * from bluetooth_info");
   ASSERT_EQ(data.size(), 1ul);
   ValidationMap row_map = {
       {"state", IntType},
       {"discoverable", IntType},
       {"address", NormalType},
       {"vendor_id", NormalType},
       {"chipset", NormalType},
       {"firmware_version", NormalType},
       {"supported_services", NormalType},
   };
   validate_rows(data, row_map);
 }

 } // namespace table_tests
 } // namespace osquery

To run the tests (and all the other tests in the repo), run cmake --build . --target test. You should get output like the following

80/82 Test #80: tools_tests_testosqueryd ..............................................   Passed   26.67 sec
      Start 81: tools_tests_testosqueryi
81/82 Test #81: tools_tests_testosqueryi ..............................................   Passed   11.62 sec
      Start 82: tests_integration_tables-test
82/82 Test #82: tests_integration_tables-test .........................................   Passed   12.70 sec

100% tests passed, 0 tests failed out of 82

Total Test time (real) = 120.39 sec

Manual verification

The key to ensuring your table works well is compiling it and running it on various Mac hardware and operating systems. Generally, I take the following approach:

    What happens when I add a third-party Bluetooth radio to the Mac (like a USB dongle?)
    What happens when I run it on a macOS VM running the latest OS?
    What happens when I run it on Apple Silicon on macOS 11 - macOS 12?
    What happens when I run it on an Intel-Based Mac running on macOS 10.9 - 12?
    Any differences between a laptop vs. a desktop (like an iMac)?

In our case, I am leaving the above exercise to the reader. Still, the testing logistics are simply compiling the project under the correct architecture, zipping up the binary, and then sending it to the device and running the same query.

I can’t tell you how many times I’ve had to go back to the drawing board after learning a crucial fact during this testing process. You should not skip it!
Step 10: Submit a PR to the Osquery Team

Okay, so while we may believe our table is the pinnacle of software engineering, it’s time for the experts to weigh in.

While we won’t actually submit this table to the team, I’ll walk you through the process I would typically go through.

Much of what I am about to go through here can be found in the excellent CONTRIBUTION.MD document in the osquery Github repository.
Check for memory leaks, code errors, and formatting

Before you submit your PR, you will want to run a bunch of automated tooling to verify you haven’t introduced memory leaks and security issues into the code-base. Getting these done before you submit a PR is an excellent signal to the team that you’ve read their contribution guide, and you generally are going to be respectful to the overall process.
Do a leaks check

For our table, this will be the most important check. We can run the check just for our table directly out of the build folder by typing:

../tools/analysis/profile.py --leaks --shell ./osquery/osqueryi --query "select * from bluetooth_info;"

If you didn’t make any changes to the source code above, you should get the following confirmation:

Analyzing leaks in query: select * from bluetooth_info;
  definitely: 0 leaks for 0 total leaked bytes.

Fix your code formatting

One other thing you should do is make sure your code is formatted like the osquery team prefers. Luckily, we can do this automatically. To auto-format your code, first stage your changes by navigating up one directory and then running git add .. (assuming you are in the build/ folder). From there, you can run cmake --build . --target format. If there were some formatting changes, you’d see something like the following:

changed files:
    tests/integration/tables/bluetooth_info.cpp

Now that your changes are staged, you can push them up to your public fork and submit your contribution as a Github Pull Request.
Write a great pull request

Writing a great PR in Github could be a whole blog post. For osquery virtual table contributions specifically, I like to generally adhere to a structure that consists of three distinct sections:
Section 1: What is this change?

In this section, I like to cover the table’s name, briefly describe what it does, and provide a sample output. For this PR, I might write something like:

  This PR implements a new Virtual Table called `bluetooth_info` which will
  report the state, discoverability of the embedded Bluetooth radio in a
  inside of Mac, along with high-level information about it.
  Here is the example output of the table on my local machine, a Macbook Pro...

Ensure you include relevant examples from at least your device and other devices you may have tested. The more detailed this is, the more confidence others will have in approving and merging your PR.
Section 2: Implementation information

Here, I like to call out how I achieved gathering the information at a high level, so the context is available to the reviewer before they look at any code. If you ran the leaks test earlier, call that out here.

  To create this table, I disassembled the system_profiler binary.
  After analyzing the executable, it appeared that the binary simply
  included `<SPSupport/SPDocument.h>` (a Private macOS framework) and calls the
  reportForDataType method with SPBluetoothDataType as the sole argument.

  This PR dynamically loads in the `SPSupport` Private Framework so that it
  can obtain the information the same way the `system_profiler` tool
  currently collects the data.

  I also checked for leaks and am happy to report this implementation appears
  to be leak-free.

  Before discovering the system_profiler, I also investigated the IOBluetooth
  framework. I found while it had private APIs that could provide similar
  information, the data these APIs were returning seemed unreliable
  and the Framework itself seemed heavily deprecated, so I quickly abandoned
  this approach.

The goal here is to head off any “what if you did this?” style questions at the pass. You want to leave the team with the accurate impression you thought about this from multiple angles and didn’t just settle on the first viable thing that worked.
Section 3: Concerns/considerations

This section will discuss anything you may be worried about in this PR that you didn’t have a chance to test earlier. You may also want to talk about any privacy concerns.

  I could use some help verifying this consistently returns data from the
  correct Bluetooth device in situations where a user may also have a Bluetooth
  radio dongle plugged in via USB. If anyone has one of those lying around and
  wants to test my table, let me know, and I'd be happy to send you a
  pre-compiled binary (or you can use the binaries compiled by the build process
  in this PR).

  While the SPSupport approach allowed me also to enumerate paired devices, I
  felt that this was not worth it. Listing devices could be a potential privacy
  issue for end-users. It reveals the name of personal objects in their vicinity
  and could be used to track a user's movements or precise geolocation.

How to be a great reviewee

There are a couple of things to keep in mind while waiting for a review that will improve your chances:

    Be responsive. When folks come in with questions or suggestions, it’s in your best interest to swiftly take action by responding and updating your code accordingly. The more responsive you are, the more likely your reviewer will be motivated to continue helping you get your PR across the finish line.

    Be Nice. It is easy to slip into a defensive mindset when something you worked hard on is being scrutinized critically by others. If someone doesn’t like the approach, do your best to understand the path forward to getting your PR mergeable. The maintainers try very hard to create a great experience for new contributors.

    Be Patient. Sometimes people are busy, and you may not get your review right away. Pinging specific reviewers on Github or Slack isn’t always a good idea. Instead, look for opportunities to get help testing your table so you can further improve it while you wait for a review. If there isn’t any natural movement for several weeks, try bringing it up respectfully in the #code-review channel on the osquery Slack. Respectful pings there are encouraged.

    Sign the CLA. When you first submit a PR, a bot will automatically flag it if you haven’t signed osquery’s CLA. It would help if you took care of that right away so reviewers know their efforts looking at the PR won’t be wasted on a last-minute licensing concern.

Additional Resources

Check out the following helpful resources you can use to continue your osquery table development journey:

    The osquery documentation has a excellent write-up for new developers looking to contribute tables.

    The osquery Github repo contains everything you need to learn by example. Just find the .cpp file that implements your favorite table and work backward from there!

    The osquery community Slack is chock full of people who can help you develop your next table. Don’t be scared to reach out for help if you get stuck!
