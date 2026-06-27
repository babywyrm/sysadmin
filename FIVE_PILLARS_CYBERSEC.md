# The Five Pillars of an Information / Cyber Security Professional ..beta.. 

> **TL;DR: "Mastering the basics will make you exceptional."**
>
> Master the fundamentals. Then specialize. Become indispensable.

---

## Table of Contents

1. [About This Document](#about-this-document)
2. [whoami](#whoami)
3. [Origin of the Five Pillars](#origin-of-the-five-pillars)
4. [Quick FAQ](#quick-faq)
5. [Security Tips to Get Started](#security-tips-to-get-started)
6. [What You Need (Equipment)](#what-you-need-equipment)
7. [The Six Pillars](#the-six-pillars)
8. [Fundamentals Breakdown](#fundamentals-breakdown)
9. [Desired Endstate of Each Pillar](#desired-endstate-of-each-pillar)
10. [A Note About Certifications](#a-note-about-certifications)
11. [Resources: How Do We Get There?](#resources-how-do-we-get-there)
12. [Pillar Specific Resources](#pillar-specific-resources)
13. [Lab Setup and Advice](#lab-setup-and-advice)
14. [Security Specific Studies and InfoSec Immersion](#security-specific-studies-and-infosec-immersion)
15. [Career Paths and Guidance](#career-paths-and-guidance)
16. [AI and LLM Awareness](#ai-and-llm-awareness)
17. [Beyond Foundations — Onto Hacking](#beyond-foundations--onto-hacking)

---

## About This Document

This document spawned an entire website. Check it out at
**[DFIRmadness.com](https://dfirmadness.com)** where you will find labs,
articles, and resources like this one. See you over there.

This document is a path forward for new — and experienced — cyber professionals
to obtain a concrete foundation of knowledge that enables success in the industry.
Mastering the basics of each functional area is required to operate on a cyber
team (or alone) in a meaningful and effective way. A lack of fundamentals in any
one pillar can quickly render a team member ineffective during dynamic and rapidly
evolving situations.

Ideally, everyone will have a specialty they excel at in addition to a solid
baseline across all fundamentals. No one person on the team should be — or can
be — a cyber unicorn. The intent is not to master every pillar completely. The
intent is to master the **fundamentals** of each. Somewhere between absolute
basics and intermediate.

As an example: a team member should understand subnetting, routing,
internetworking, the OSI model, packet capture, DNS, and analysis basics. This
does not mean they need to be a Cisco network engineer with a CCNA.

**Layout of this document:**

- Fundamentals and getting started
- Lab setup advice
- Security focused training and immersion
- Security career pathways
- AI and LLM awareness

---

## whoami

- 🐦 **Twitter/X:** [@DFIRmadness](https://twitter.com/DFIRmadness)
- Veteran
- Former Pilot
- Senior Information Security Professional
- Perpetual n00b (always learning)
- Adjunct Professor
- SANS Instructor

I have seen folks across multiple industries who would be absolute rockstars if
they had a solid mastery of all the basics — rather than being pigeon-holed into
one niche of the field. This document exists to fix that.

---

## Origin of the Five Pillars

I did not come up with the five pillars idea on my own. I first heard the concept
during a conversation connected to the SANS CyberStart program. The five areas
resonated immediately because they aligned with something I already believed
deeply:

> *"Master the basics to become exceptional."*

That idea was hammered home during a memorable correction delivered during Special
Forces training. Between flutter kicks and sprints, an instructor told us:

> *"We look special because we master the basics."*

I have applied that principle to every complex thing I have ever learned — from
flying helicopters to hacking networks — and it has served me well every single
time.

---

## Quick FAQ

### Where is the hacking?! I don't see any hacking in the pillars!

Correct. These are the **fundamentals** that both offense and defense require.
You cannot exploit what you don't understand. You cannot defend what you can't
operate. Build the foundation first. The house comes after.

### Do I need a degree?

No. You do not need a degree in cyber security. Read that again.

If you feel compelled to get a degree, get one in **Computer Science**. There are
far too many people with Cyber Security degrees who cannot find their way around a
command line and know only academic theory. They talk the talk without being able
to walk the walk. Most programs do not provide nearly enough hands-on fundamentals
to set someone up for success.

### What about certification pipelines and "career in 6 weeks" schools?

The cert farms that promise you A+, Net+, Sec+, and CEH in six weeks — for
$15,000 to $20,000 — are stealing your money. Certifications matter and you will
likely need some, but you do **not** need five certs in five weeks. If you find a
program that claims to teach the fundamentals laid out in this document, ask to
speak to alumni and verify that the instructors are actual industry professionals
with real time in the trenches.

### What about AI? Is this field even relevant with LLMs everywhere?

More relevant than ever. AI has changed the threat landscape and the defender's
toolkit — but it has not eliminated the need for humans who understand
fundamentals. In fact, professionals who understand the basics are now the ones
best positioned to leverage AI effectively and catch AI-assisted attacks. There is
a dedicated section on AI and LLM awareness later in this document.

### What about the allure of penetration testing?

Maybe penetration testing is the only thing that interests you. Maybe catching bad
guys is your entire motivation. Both are valid starting points. Keep this in mind:

- Learning **both sides** of the equation makes you better at either one
- The better your understanding of defense, the more effective you are on offense
- There are roughly **10 Blue (defense) jobs for every 1 Red (offense) job**
- Penetration testing is genuinely a blast — and a lot of work. It is not simply
  pwning networks and dropping mics.

There are incredible, fulfilling careers across the entire spectrum of this field.
Keep an open mind as you build your foundation.

---

## Security Tips to Get Started

As you dive into security you should immediately start practicing good personal
security hygiene. Practice what you preach from day one.

- 🚫 Don't pirate software
- 🔐 Keep your admin account separate from your daily driver account
- 🔗 Never click a link you didn't ask for
- 🚫 Never use a free VPN — **Mullvad** and **Proton VPN** are solid paid options
- 🦠 Always check executables and files from others at
  [virustotal.com](https://virustotal.com)
- 🔑 Use **passkeys** wherever supported — they are the future of authentication
- 📱 Use **hardware security keys** (e.g. YubiKey) for critical accounts like
  email
- 🔒 Use time-based multi-factor authentication on any account that doesn't
  support passkeys
- 🗄️ Use a **password manager** with unique passwords for everything
- 💬 Use passphrases when passwords are required — Example:
  `1DeerCloudSubmarine91!`
  [XKCD Password Generator](https://xkcdpassword.com)
- 🤖 Be skeptical of AI-generated phishing — it is now indistinguishable from
  legitimate email. Verify out-of-band when anything feels off.

---

## What You Need (Equipment)

You do not need a $3,000 gaming laptop or a desktop with dual GPUs and 10TB of
SSD storage. This is entirely budget dependent. You can start with $500 if needed.

| Level | Budget | What You Get |
|---|---|---|
| **Good** | ~$500 | A machine capable of web browsing and reading. You'll rely on cloud-based labs instead of local VMs. The trade-off is worth it to get started. |
| **Better** | ~$1,100 | A laptop capable of running 2–3 Virtual Machines locally. Target: i7 or Ryzen 7, 16GB RAM, 500GB SSD. |
| **Best** | $1,800+ | Full local cyber range capability. i9 or Ryzen 9, 32GB+ RAM, 1TB+ SSD. A mid-tier GPU is a bonus for password cracking but absolutely not required. |

> **Note on GPUs:** A GPU is useful for password cracking. You do **not** need
> one to learn or level up in cyber security. You get the same training value
> cracking a simple password with your CPU as you do watching a GPU churn on a
> hash for two weeks. Don't let hardware be a barrier to entry.

> **Note on Virtualization Software:** VMware Workstation Pro is now 
> **free for personal use** following Broadcom's acquisition. VirtualBox remains 
> free and open source. For serious home labs, **Proxmox** has become the 
> community standard — it's free, powerful, and runs on bare metal.

---

## The Six Pillars

To start — or level up — a career in Information Security you need to be
proficient in six key functional areas. You don't need to master each one, but
you need a solid working understanding of all of them. Whether you want to go
offense or defense, you will need to be functional across all six:

1. 🖥️ **General Computing**
2. 🌐 **Computer Networking**
3. 💻 **Scripting and Programming**
4. 🪟 **Windows**
5. 🐧 **Linux / MacOS**
6. ☁️ **Cloud Computing**

> **Why Cloud?** When the original five pillars were written, cloud was emerging.
> In 2026 it is the default operating environment for most organizations. You
> cannot operate meaningfully on a modern security team without a baseline
> understanding of cloud infrastructure, IAM, and cloud-native attack surfaces.
> Cloud earns its place as a full pillar.

---

## Fundamentals Breakdown

The following are key skill sets within each pillar. This is not an exhaustive
list — it is a map of the terrain.

### 🖥️ General Computing

| Category | Skills |
|---|---|
| **Hardware** | CPU, RAM, SSD/HDD, GPU |
| **Operating System Concepts** | Threads, Processes, Process Trees |
| **Memory** | RAM vs Disk, Caching, Buffers, Memory Paging |
| **Execution** | How programs are loaded and run |

### 🌐 Computer Networking

| Category | Skills |
|---|---|
| **Models** | OSI Model (all 7 layers), TCP/IP Model |
| **Protocols** | TCP vs UDP, DNS, ARP, DHCP, HTTP/S, SSH, FTP |
| **Analysis** | Packet Capture, Packet Analysis, Wireshark |
| **Infrastructure** | Routing, Subnets, VLANs |
| **Security** | Firewalls, IDS/IPS concepts, Network Segmentation |

### 💻 Scripting and Programming

| Category | Skills |
|---|---|
| **Languages** | Python, PowerShell, Bash |
| **Concepts** | Variables, Loops, Functions, File I/O, Error Handling |
| **Regex** | Pattern matching — used constantly in log analysis and tooling |
| **Bonus** | C, C#, or Go for deeper systems work |
| **AI-Assisted Coding** | Using LLMs to write and review scripts — and understanding their limitations and risks |

### 🪟 Windows

| Category | Skills |
|---|---|
| **Architecture** | Registry (5 Hives), DLLs, .msi vs .exe, Volume Shadow Copies |
| **Security** | UAC, SIDs, RIDs, Tokens, Network Profiles |
| **Memory** | Memory Paging, Virtual Memory |
| **Networking** | Server vs Workstation, PowerShell Remoting |
| **CLI Commands** | `netstat`, `whoami`, `ping`, `ipconfig`, `tasklist`, `net user` |
| **Tools** | Sysinternals Suite, Process Hacker / System Informer |

### 🐧 Linux

| Category | Skills |
|---|---|
| **File System** | Directory Hierarchy, Permissions, File Types |
| **Users & Auth** | `sudo`, `/etc/shadow`, `/etc/passwd`, User Groups |
| **Remote Access** | SSH, FTP, Telnet (and why not to use it) |
| **Package Management** | Software Repositories, `apt`, `yum`, `dnf` |
| **Distros to Know** | Kali, Ubuntu, Debian, CentOS, Rocky Linux, Parrot OS |
| **CLI Commands** | `w`, `find`, `whoami`, `which`, `who`, `ss`, `watch`, `lsof`, `top`, `htop`, `sudo`, `nano`, `vim`, `grep`, `awk`, `cut`, `chmod`, `chown` |

### ☁️ Cloud Computing

| Category | Skills |
|---|---|
| **Platforms** | AWS, Azure, GCP — understand at least one deeply |
| **Core Concepts** | IAM (Identity and Access Management), Regions, Availability Zones |
| **Services** | Compute (EC2/VMs), Storage (S3/Blobs), Networking (VPCs) |
| **Security** | Shared Responsibility Model, Security Groups, CloudTrail/logging |
| **Containers** | Docker basics, Kubernetes awareness |
| **Attack Surface** | Misconfigured buckets, over-permissioned roles, metadata service abuse |

---

## Desired Endstate of Each Pillar

These are your goalpost targets. If you can meet each of these you are a
competent professional ready to shine in interviews and be an asset to any team.

| Pillar | Target Endstate |
|---|---|
| **General Computing** | Explain the difference between something stored in memory vs on disk. Explain the basics of process injection. Explain the difference between killing a thread vs killing a process. |
| **Networking** | Using all 7 layers of the OSI model, walk through exactly what happens — at every layer — when you type `ping google.com` and hit Enter. Explain what a VLAN is and why it exists. Explain subnetting and the security value of network segmentation. |
| **Scripting & Programming** | Write a basic script to automate a simple task. Read someone else's script and explain what it is doing at a high level. Use an LLM to help you write and debug scripts — while understanding where AI-generated code can introduce vulnerabilities. |
| **Windows** | Explain the function of the registry, UAC, and access tokens. Navigate the OS using command line only. Identify active network connections and their associated processes. Demonstrate basic PowerShell capability. |
| **Linux** | Explain sudo, the shadow and passwd files, and user groups. Install and manage software via repositories. Navigate the OS using command line only. Identify active network connections and their associated processes. |
| **Cloud** | Explain the shared responsibility model. Identify and explain IAM roles and policies. Recognize common cloud misconfigurations. Explain what a VPC is and how security groups function as a cloud-native firewall. |

> Remember: you have to know how things work to exploit them. You have to know
> what *right* looks like to find the gaps.

---

## A Note About Certifications

Certifications are a necessity in this industry. In many cases they are more
immediately valuable than a college degree for getting through a hiring filter.
That said:

- Don't be a **paper tiger** — a wall of certs with no practical ability behind
  them will fail you the moment you sit in front of a keyboard in an interview or
  on the job.
- Don't fall for the **cert farm trap** — companies that promise a career-ready
  professional in five weeks for $20K are not delivering on that promise.
- Certs mentioned throughout this document are often just excellent **bodies of
  knowledge** — you can gain enormous value from the study materials without
  sitting the exam.

### Certs to Shoot for Early On

| Cert | Notes |
|---|---|
| **CompTIA Security+** | Entry level, widely recognized, satisfies DoD 8140/8570 requirements. Good starting point. |
| **GIAC GSEC** | More expensive but far more respected and rigorous than Sec+. Worth every penny if your employer pays. |
| **PNPT (TCM Security)** | Practical Network Penetration Tester. Affordable (~$400), practical exam format, rapidly gaining industry respect. Excellent alternative to CEH. |
| **BTL1 (Blue Team Labs)** | Blue Team Level 1. Affordable, practical, and one of the best entry-level defensive certs available. |
| **AZ-900 / AWS Cloud Practitioner** | Cloud fundamentals cert. Cheap, quick, and shows cloud baseline awareness. |

### Certs to Avoid (Early On)

| Cert | Why |
|---|---|
| **A+** | Friends don't let friends actually pursue the A+ cert. The material is useful. The cert itself will not help your career in security. |
| **CEH** | Does not make you a penetration tester. Barely recognized outside of DoD checkbox exercises. For the same money, buy the PWK/OSCP course from Offensive Security. The material and labs will do far more for you. |

### Certs to Aspire To

| Cert | Domain |
|---|---|
| **OSCP (Offensive Security)** | Penetration Testing — still the gold standard |
| **GPEN / GWAPT (SANS)** | Network and Web App Penetration Testing |
| **GCFA / GCFE (SANS)** | Digital Forensics |
| **GCIH (SANS)** | Incident Handling |
| **GCIA (SANS)** | Network Forensics / Intrusion Analysis |
| **GREM (SANS)** | Malware Reverse Engineering |
| **CCD (Certified Cyberdefender)** | Blue Team — newer cert gaining strong traction |
| **SC-200 (Microsoft)** | Security Operations Analyst — highly relevant for SOC roles |

> **SANS Tip:** SANS courses run $6,000–$8,000+. Look into becoming a **SANS
> facilitator** — by volunteering your time to help courses run, you can attend
> for around $1,500. That is an extraordinary deal.

---

## Resources: How Do We Get There?

Take a moment to think about how you approach learning a mountain of information.
Watch: [How to Learn Anything Fast — Josh Kaufman](https://www.youtube.com/watch?v=5MgBikgcWnY)

### General Approach

1. **Start free and cheap** to verify you actually enjoy this. You may find it
   isn't for you — and that's fine to discover early.
2. **Get hands on keyboard.** Do not just read. Labs and practice are not
   optional. Do both simultaneously.
3. **Sprinkle in security lessons** alongside your general studies from day one.
4. **Rotate through all six pillars** rather than going deep on one and ignoring
   the others for months. These skills are perishable. If you haven't touched
   networking in five months it will be rusty and you will have to relearn it.
5. **Try to have fun.** This field is genuinely fascinating if you let it be.
6. **Keep an eye out for your passion.** You will want to specialize eventually.
   Pay attention to what lights you up.

### Recommended Security-Focused Resources for General Studies

#### 📘 Hack and Detect
**[Hack and Detect](https://www.amazon.com/dp/B07QQGHJJF)** by Nik Alleyne.

The book to start with. Available for purchase or free with Kindle Unlimited. It
cannot be recommended enough for beginners and experienced folks alike. It
presents both offense and defense methodologies with breakdowns and explanations
of every command. Consider it the quick-start guide into security — read it
alongside your five pillar studies.

#### 🎬 TCM Security / The Cyber Mentor
**[TCM Security Academy](https://academy.tcm-sec.com)**

Heath Adams (The Cyber Mentor) has built one of the best practical security
curriculums available anywhere — at a fraction of the cost of competitors. His
courses cover penetration testing, Active Directory attacks, OSINT, malware
analysis, and more. Even if you want to go blue team, understanding how attackers
move through a network is essential knowledge. Start here.

#### 🎬 TryHackMe
**[TryHackMe](https://tryhackme.com)**

The single best starting point for absolute beginners in 2026. Guided learning
paths, browser-based labs (no local setup required), and a structured progression
from zero to job-ready. Has both free and paid tiers. The paid tier (~$14/month)
is worth every penny. Start with the **Pre-Security** or **SOC Level 1** learning
path depending on your interest.

#### 🎬 13Cubed
**[13Cubed on YouTube](https://www.youtube.com/@13Cubed)**

Hands down one of the best DFIR (Digital Forensics and Incident Response) YouTube
channels in existence. Richard Davis breaks down forensics concepts clearly,
practically, and with real-world relevance. Required watching for anyone
interested in the blue team / forensics side of the house.

#### 🎬 John Hammond
**[John Hammond on YouTube](https://www.youtube.com/@_JohnHammond)**

Malware analysis, CTF walkthroughs, career advice, and a genuinely entertaining
teaching style. One of the most well-rounded security educators online today.

---

## Pillar Specific Resources

### 🖥️ General Computing

| Resource | Notes |
|---|---|
| [Professor Messer A+ Videos](https://www.professormesser.com) | Free. You are NOT getting the cert. Use this for the concepts. |
| [Computerphile (YouTube)](https://www.youtube.com/@Computerphile) | PhD-level computer science and security concepts explained accessibly. Absolute gem of a channel. |
| [Threads vs Processes — Georgia Tech / Udacity](https://www.udacity.com) | Short video. Watch it multiple times. |
| [Crash Course Computer Science (YouTube)](https://www.youtube.com/playlist?list=PL8dPuuaLjXtNlUrzyH5r6jN9ulIgZBpdo) | Free. Excellent visual explanations of core computing concepts. |

### 🌐 Computer Networking

| Resource | Notes |
|---|---|
| [Professor Messer Network+](https://www.professormesser.com) | Free. Solid fundamentals coverage. |
| [Todd Lammle Internetworking Fundamentals](https://www.itpro.tv) | 15 minute video. Watch it often. One of the best rapid networking overviews available. |
| [malware-traffic-analysis.net](https://malware-traffic-analysis.net) | Free collection of PCAPs filled with malicious traffic plus tutorials. Pair with Wireshark. |
| [Cisco Packet Tracer](https://www.netacad.com/courses/packet-tracer) | Free network simulation software with free intro courses. Build and break virtual networks. |
| [Microsoft Network Fundamentals (YouTube)](https://www.youtube.com) | Concise, accurate, free. |
| [TryHackMe — Pre-Security Path](https://tryhackme.com) | Covers networking fundamentals in a hands-on guided format. |

### 💻 Scripting and Programming

| Resource | Notes |
|---|---|
| [Learn Python — learnpython.org](https://learnpython.org) | Free. Good interactive intro. |
| [Programming with Mosh — Python](https://www.youtube.com/watch?v=_uQrJ0TkZlc) | Free 6-hour Python course on YouTube. Gets you functional fast. |
| [Google's Python Class](https://developers.google.com/edu/python) | Free. Solid fundamentals with exercises. |
| [Under The Wire](https://underthewire.tech) | CTF-style PowerShell challenges. The most fun way to learn PowerShell. |
| [PoSh-Hunter](https://posh-hunter.com) | Jeopardy-style CTF for PowerShell in an InfoSec context. |
| [Bash Scripting Tutorial](https://linuxconfig.org/bash-scripting-tutorial) | Free. Work through the basics. |
| [Regex101](https://regex101.com) | Free interactive regex builder and tester. Learn regex here. You will use it constantly. |

### 🪟 Windows

| Resource | Notes |
|---|---|
| [TCM Security — Practical Ethical Hacking](https://academy.tcm-sec.com) | Covers Windows and Active Directory extensively in a practical context. |
| [Microsoft Learn — Windows Server](https://learn.microsoft.com) | Free. Official Microsoft training. More depth than you'll need early on but a great reference. |
| [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/) | Free toolkit from Microsoft. Learn every tool in here. Process Monitor, Autoruns, and TCPView are essential. |
| [PoSh-Hunter](https://posh-hunter.com) | PowerShell CTF challenges in a security context. |
| [TCM — Active Directory Hacking Lab](https://academy.tcm-sec.com) | Step-by-step guide to building and attacking an AD lab. Foundational for any Windows security work. |
| [TryHackMe — Windows Fundamentals](https://tryhackme.com) | Guided, browser-based Windows fundamentals path. |

### 🐧 Linux

> **Recommended starting distro: Ubuntu**

| Resource | Notes |
|---|---|
| [Over The Wire — Bandit](https://overthewire.org/wargames/bandit/) | The most fun way to learn Linux. Levels 0–10 are a solid intro. Keep going. |
| [Linux Journey](https://linuxjourney.com) | Free. Browser-based labs. Do this anywhere. Beautifully structured. |
| [TCM Security — Linux Fundamentals](https://academy.tcm-sec.com) | Heath Adams' Linux course. Well structured for beginners. |
| [Kali Linux Revealed — Free PDF](https://kali.training/downloads/Kali-Linux-Revealed-1st-edition.pdf) | Free legitimate PDF download. A professional-grade book on Linux in a security context. |
| [TryHackMe — Linux Fundamentals](https://tryhackme.com) | Three-part guided path. Browser-based. No local setup required. |

### ☁️ Cloud Computing

| Resource | Notes |
|---|---|
| [AWS Cloud Practitioner Essentials](https://aws.amazon.com/training/) | Free official AWS training. Start here for AWS. |
| [Microsoft Learn — AZ-900](https://learn.microsoft.com) | Free official Azure fundamentals training. |
| [TryHackMe — Cloud Security Path](https://tryhackme.com) | Emerging path covering cloud attack and defense concepts. |
| [flaws.cloud](http://flaws.cloud) | Free AWS-specific security challenge. Learn by exploiting common misconfigurations. |
| [flaws2.cloud](http://flaws2.cloud) | Follow-on to flaws.cloud with attacker and defender perspectives. |
| [CloudGoat (Rhino Security Labs)](https://github.com/RhinoSecurityLabs/cloudgoat) | Free intentionally vulnerable AWS environment for practice. |

---

## Lab Setup and Advice

There are two approaches to a lab environment:

1. **Local** — built on your laptop or a home server
2. **Remote** — cloud-hosted or platform-provided environments you connect to

### Local Lab

Building a local lab is one of the most educational things you can do. The
process of setting it up teaches you concepts you simply cannot absorb from
reading alone.

#### Virtualization Software Options

| Software | Cost | Notes |
|---|---|---|
| **VMware Workstation Pro** | Free (personal use) | Broadcom made it free for personal use. More stable and performant than VirtualBox. |
| **VirtualBox** | Free | Open source. Cross-platform. Solid for beginners. Occasional quirks. |
| **Proxmox VE** | Free | The community standard for serious home labs. Runs on bare metal. Manage multiple VMs and containers from a web UI. Steep initial learning curve with a huge payoff. |

#### Where to Get Vulnerable VMs

| Resource | Notes |
|---|---|
| [VulnHub](https://www.vulnhub.com) | Free collection of intentionally vulnerable VMs. Download, import, attack. Many include walkthroughs. |
| [VulnHub Lab Guide](https://www.vulnhub.com/lab/) | Guided tour on building a home pentesting lab from VulnHub. |

#### Sample Local Cyber Range Layout

A well-equipped local range that runs on a decent laptop might look like this:

```text
┌─────────────────────────────────────────────────────────────┐
│                     INTERNAL SUBNET                         │
│                                                             │
│  ┌──────────────────┐     ┌──────────────────┐              │
│  │  Windows Domain  │     │  Windows Client  │              │
│  │   Controller     │────▶│  (Domain Joined) │              │
│  └──────────────────┘     └──────────────────┘              │
│                                                             │
│  ┌──────────────────┐                                       │
│  │  Vulnerable Web  │◀────────────────────────────────┐     │
│  │  Server (dual    │                                  │    │
│  │  homed)          │                                  │    │
└──┤                  ├──────────────────────────────────┼────┘
   └──────────────────┘                                  │
                                                         │
┌─────────────────────────────────────────────────────────────┐
│                     EXTERNAL SUBNET                         │
│                                                             │
│  ┌──────────────────┐                                       │
│  │   Kali Linux     │─────────────────────────────────┘     │
│  │  (Attack Box)    │                                       │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

The Kali machine can be moved to the internal subnet to simulate insider threat
or post-compromise lateral movement scenarios.

### Remote Labs

Remote labs give you a fully built environment to connect to without needing
powerful local hardware. This is a legitimate and effective way to learn.

| Platform | Cost | Notes |
|---|---|---|
| [TryHackMe](https://tryhackme.com) | Free / ~$14/mo | Browser-based. Guided paths. Best for beginners. No VPN required. |
| [Hack The Box](https://hackthebox.com) | Free / ~$14/mo | One of the most popular pentesting lab environments. Community is excellent. Discord is invaluable. |
| [HTB Academy](https://academy.hackthebox.com) | Free / paid tiers | Structured learning paths from HTB. More guided than the main platform. |
| [Blue Team Labs Online](https://blueteamlabs.online) | Free / paid | Excellent blue team focused labs. Fills the defensive gap that many platforms miss. |
| [LetsDefend](https://letsdefend.io) | Free / paid | SOC analyst simulation. Alert triage, log analysis, incident response practice. |
| [PentesterLab](https://pentesterlab.com) | Free / ~$20/mo | Web application security focused. High quality walkthroughs and ISO downloads. |

---

## Security Specific Studies and InfoSec Immersion

**Start your immersion immediately.** Do not wait until you feel "ready." You
will never feel ready. Jump in now.

### Training Companies

#### SANS Institute
**[sans.org](https://www.sans.org)**

Hands down the best security training on the planet. Instructors are highly
vetted security professionals with real operational experience in the topics they
teach. They are expensive — $6,000 to $8,000+ per course.

**Tips for getting SANS training affordably:**
- Look into becoming a **SANS facilitator** — volunteer your time to support
  course delivery and attend for ~$1,500
- Watch for **work authorization** — many employers will pay for SANS if you
  negotiate it into an offer or annual training budget
- **OnDemand** courses can sometimes be found at reduced rates

A SANS cert (GIAC) is recognized immediately across the industry as a genuine
demonstration of skill — not just a checkbox.

#### TCM Security
**[tcm-sec.com](https://tcm-sec.com)**

Practical, affordable, industry-respected. Heath Adams has built one of the best
security training ecosystems outside of SANS. Courses range from $30–$60 each.
The **PNPT certification** is rapidly becoming a respected alternative to OSCP
for penetration testing roles.

#### Offensive Security (OffSec)
**[offsec.com](https://offsec.com)**

Home of the OSCP — still the gold standard penetration testing certification.
PWK (Penetration Testing with Kali Linux) is their foundational course. The labs
are extensive and the exam is brutal in the best way. Even if you cannot pass the
OSCP challenge immediately, the course material and lab time are worth the cost.

### YouTube Channels

| Channel | Focus |
|---|---|
| [The Cyber Mentor](https://www.youtube.com/@TCMSecurityAcademy) | Penetration testing, beginners through advanced, career advice |
| [John Hammond](https://www.youtube.com/@_JohnHammond) | Malware analysis, CTFs, career content, incredibly well-rounded |
| [13Cubed](https://www.youtube.com/@13Cubed) | DFIR, Windows forensics, memory forensics — essential for blue teamers |
| [LiveOverflow](https://www.youtube.com/@LiveOverflow) | Complex hacking concepts broken into digestible pieces |
| [IPPSec](https://www.youtube.com/@ippsec) | HTB machine walkthroughs — one of the best teachers in the game |
| [NahamSec](https://www.youtube.com/@NahamSec) | Bug bounty, web application hacking, OSINT |
| [Computerphile](https://www.youtube.com/@Computerphile) | Computer science and security concepts from academics |
| [David Bombal](https://www.youtube.com/@davidbombal) | Networking, Python, ethical hacking — great interview content |
| [Security Weekly](https://www.youtube.com/@SecurityWeekly) | Industry news, interviews, technical segments |

### Podcasts

| Podcast | Notes |
|---|---|
| [Darknet Diaries](https://darknetdiaries.com) | Storytelling-style security podcast. Mandatory listening. Start from episode 1. |
| [Security Now](https://twit.tv/shows/security-now) | Steve Gibson and Leo Laporte. Deep technical dives on current security topics. |
| [Smashing Security](https://www.smashingsecurity.com) | Lighter tone, current security news and stories. |
| [SANS Internet Stormcast](https://isc.sans.edu/podcast.html) | Daily 5-minute security news briefing. Subscribe and never miss one. |
| [Brakeing Down Security](https://www.brakeingsecurity.com) | One of the best collections of security discussion and community. |
| [The CyberWire Daily](https://thecyberwire.com) | Professional daily briefing on the threat landscape. |
| [Risky Business](https://risky.biz) | Industry veteran Patrick Gray interviewing the best minds in security. |

### Communities

| Community | Platform | Notes |
|---|---|---|
| TCM Security | Discord | Active, welcoming, beginner-friendly |
| Hack The Box | Discord | Large, active, great for getting unstuck on machines |
| TryHackMe | Discord | Excellent beginner community |
| Brakeing Down Security | Slack | One of the best long-running InfoSec community Slack workspaces |
| SANS | Discord / Forums | Networking with industry professionals |

### Social Media / People to Follow

> Many in the community have diversified across platforms. Check LinkedIn and
> Bluesky in addition to X/Twitter.

| Handle | Known For |
|---|---|
| @thecybermentor | Penetration testing, career advice, education |
| @MalwareJake (Jake Williams) | Incident response, threat intelligence |
| @malware_traffic (Brad Duncan) | Network forensics, PCAP analysis |
| @ippsec | HTB walkthroughs, practical hacking |
| @Fox0x01 (Azeria) | ARM exploitation, mobile security |
| @hacks4pancakes (Lesley Carhart) | ICS/SCADA security, career advice |
| @securityweekly (Paul Asadoorian) | Security Weekly podcast, community |
| @robtlee (Rob Lee) | SANS, DFIR, ICS security |
| @edskoudis (Ed Skoudis) | SANS, penetration testing legend |
| @sansforensics | DFIR news and resources from SANS |
| @MalwareTechBlog (MalwareTech) | Malware analysis, threat research |
| @malwareunicorn | Malware analysis, reverse engineering education |
| @NahamSec | Bug bounty, web hacking |
| @JackRhysider | Darknet Diaries podcast |
| @LiveOverflow | CTF, hacking concepts |
| @TinkerSec | Red team, creative attack techniques |
| @KodyKinzie | Wireless security, creative hacking |

---

## AI and LLM Awareness

This section did not exist in the original document. It exists now because
ignoring AI in a security fundamentals guide in 2026 would be malpractice.

### The Honest Reality

AI has not replaced security professionals. It has:

- Made **attackers more capable** at scale — phishing is now indistinguishable
  from legitimate communication, social engineering is personalized and automated,
  and malware development has been accelerated
- Made **defenders more capable** — log analysis, alert triage, threat intel
  summarization, and code review can all be augmented meaningfully
- Created **entirely new attack surfaces** — LLM systems themselves can be
  attacked via prompt injection, data poisoning, and model theft

The professionals who thrive in this new environment are those who understand the
fundamentals **and** know how to leverage AI tools effectively.

### What You Need to Know

#### AI as an Attacker Tool

| Threat | What It Means |
|---|---|
| **AI-Generated Phishing** | Perfectly written, contextually relevant, personalized phishing at industrial scale. Traditional grammar/spelling red flags are gone. |
| **Deepfake Voice / Video** | Attackers impersonating executives or IT personnel in real-time calls or pre-recorded messages. Already used in successful fraud. |
| **AI-Assisted Malware** | LLMs used to generate, modify, and obfuscate malware to evade signature-based detection. |
| **Automated Reconnaissance** | AI agents that autonomously enumerate attack surface, identify vulnerabilities, and plan attack chains. |
| **Prompt Injection** | Attackers embedding malicious instructions in content that LLM-powered tools will process — causing the AI to take unintended actions. |

#### AI as a Defender Tool

| Use Case | What It Means |
|---|---|
| **Log Analysis** | LLMs can help parse, summarize, and identify anomalies in large volumes of log data faster than manual review. |
| **Alert Triage** | AI-assisted SOC tools help analysts prioritize and contextualize alerts. Understand how these tools work — and their failure modes. |
| **Threat Intel Summarization** | Rapidly summarizing threat reports, CVE advisories, and IOC lists. |
| **Script Generation** | Using LLMs to write automation scripts, detection rules, and queries. |
| **Explaining Malware** | Tools like AI-assisted disassemblers can explain what malicious code is doing faster than ever. |

#### New Attack Surface: AI Systems Themselves

| Attack | Description |
|---|---|
| **Prompt Injection** | Injecting instructions into LLM inputs to hijack behavior. Analogous to SQL injection but for AI systems. |
| **Indirect Prompt Injection** | Attacker places malicious instructions in a document, email, or webpage that an LLM agent will later process. |
| **Model Inversion** | Extracting training data from a model through clever querying. |
| **Data Poisoning** | Corrupting training data to influence model behavior in production. |
| **Jailbreaking** | Bypassing safety guardrails to elicit policy-violating outputs. |

### Practical Guidance

- **Use LLMs in your workflow** — they are legitimate force multipliers for
  learning and working. Use them to explain concepts, debug scripts, and
  summarize documentation.
- **Never trust AI-generated code without reviewing it** — LLMs produce
  plausible-looking code that can contain subtle vulnerabilities. You need the
  fundamentals to catch them.
- **Verify everything out-of-band** — if an email, call, or message asks you to
  do something sensitive or unusual, verify through a separate channel you
  initiated yourself. AI-generated impersonation is that good now.
- **Learn prompt injection** — understand how it works as both an attacker
  technique and a class of vulnerability you may need to find and fix in
  applications your organization builds or uses.
- **Stay current** — this space moves faster than any other area of security.
  Follow researchers working in AI security.

### Resources for AI Security

| Resource | Notes |
|---|---|
| [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | The definitive starting point for understanding LLM application security risks |
| [Prompt Injection Primer](https://github.com/jthack/PIPE) | Practical introduction to prompt injection attacks |
| [AI Village (DEF CON)](https://aivillage.org) | Annual DEF CON village dedicated to AI security research |
| [Adversarial ML Threat Matrix](https://github.com/mitre/advmlthreatmatrix) | MITRE's framework for adversarial machine learning attacks |
| [Simon Willison's Blog](https://simonwillison.net) | One of the best ongoing resources for LLM security research and prompt injection |

---

## Career Paths and Guidance

### How to Decide

As you work through the fundamentals you will naturally find topics that light you
up. Pay attention to that. All of the following paths are simply different flavors
of hacker. They are all vital. A healthy security team needs all of them.

### The Roles

#### 🔴 Red Team (Offensive Security)

| Role | Description |
|---|---|
| **Penetration Tester** | Find and validate vulnerabilities by demonstrating real attacks. Report findings. Help fix them. |
| **Red Team Operator** | Emulates realistic threat actors over longer engagements. Focused on stealth, persistence, and evading detection rather than simply finding vulnerabilities. |
| **Exploit Developer** | Finds vulnerabilities in software and develops working exploits. Requires deep programming and systems knowledge. |
| **Bug Bounty Hunter** | Independent security researcher who finds vulnerabilities in exchange for monetary rewards from companies running bug bounty programs. |
| **Social Engineer** | Specializes in the human element — phishing, vishing, physical access. Part of red team engagements. |

#### 🔵 Blue Team (Defensive Security)

| Role | Description |
|---|---|
| **SOC Analyst** | Monitors and triages security alerts. The front line of defense. Tier 1/2/3 progression. |
| **Incident Responder** | Called in when something goes wrong. Contain, eradicate, recover, and document. High-stress, high-reward. |
| **Digital Forensics Analyst** | Examines systems, memory, network traffic, and storage media to reconstruct events. |
| **Threat Hunter** | Proactively searches for attacker activity that automated tools haven't detected. Requires deep knowledge of attacker TTPs. |
| **Threat Intelligence Analyst** | Tracks threat actors, campaigns, and TTPs. Produces intelligence to inform the team's defenses. |
| **Security Engineer** | Designs and builds security infrastructure — SIEM, EDR, logging pipelines, detection rules, automation. |
| **Malware Analyst / Reverse Engineer** | Dissects malware to understand what it does, how it works, and how to detect and stop it. |

#### 🟣 Purple / Adjacent Roles

| Role | Description |
|---|---|
| **Cloud Security Engineer** | Secures cloud infrastructure. IAM, misconfig detection, CSPM tooling, cloud-native incident response. Massive demand in 2026. |
| **AppSec / Product Security Engineer** | Embeds in software development teams to find and fix security issues before code ships. |
| **GRC Analyst** | Governance, Risk, and Compliance. Less technical, more process and policy oriented. High hiring volume. Often a path for career changers. |
| **AI Security Researcher** | Emerging role. Focuses on securing AI/ML systems and researching AI-specific attack techniques. Real jobs exist now. |
| **Security Awareness / Trainer** | Develops and delivers security training programs for non-technical staff. Communication skills over technical depth. |

### Typical Career Path

```text
IT Help Desk
    │
    ▼
Systems Administrator
    │
    ▼
Security Administrator / Junior SOC Analyst
    │
    ├──▶ Penetration Tester / Red Team
    ├──▶ Incident Response / DFIR
    ├──▶ Threat Hunting
    ├──▶ Cloud Security Engineer
    ├──▶ Security Engineer
    └──▶ Malware Analyst / Reverse Engineer
```

You can skip rungs on this ladder — but the more rungs you skip the harder you
need to work to make up the foundational knowledge those roles would have built.

### Salary Reality Check (2026)

> These are rough US market figures. Actual compensation varies significantly by
> geography, company size, clearance level, and specialization.

| Level | Approximate Range |
|---|---|
| Entry Level (0–2 years) | $75,000 – $100,000 |
| Mid Level (3–5 years) | $100,000 – $140,000 |
| Senior (6–10 years) | $140,000 – $180,000 |
| Principal / Staff | $180,000 – $250,000+ |
| Cleared (TS/SCI) | Add $20,000 – $40,000 to above ranges |

### General Bodies of Knowledge by Role

#### Engineering / Security Engineering

| Category | Details |
|---|---|
| **Certifications** | GSEC, Linux+, AZ-900 or AWS Cloud Practitioner |
| **Skills** | Linux admin, Bash, Python, networking, cloud fundamentals, SIEM configuration |

#### DFIR (Digital Forensics and Incident Response)

| Category | Details |
|---|---|
| **Certifications** | GSEC, GCFE, GCFA, GCIH, GCIA, Sec+, CySA+, BTL1 |
| **Skills** | Windows internals, Linux security, memory forensics, network forensics, digital forensics tooling, threat hunting, timeline analysis |

#### Malware Reverse Engineering

| Category | Details |
|---|---|
| **Certifications** | GREM |
| **Skills** | Assembly, C, Python, Windows internals, Linux security, static and dynamic analysis, sandbox environments, IDA Pro / Ghidra |

#### Penetration Testing

| Category | Details |
|---|---|
| **Certifications** | PNPT, OSCP, GPEN, GWAPT, PenTest+ |
| **Skills** | Linux, Windows, Python, Bash, networking, Active Directory, web application testing, report writing |

#### Cloud Security

| Category | Details |
|---|---|
| **Certifications** | AZ-500, AWS Security Specialty, CCSP, GCPN |
| **Skills** | Cloud platform depth (AWS/Azure/GCP), IAM, CSPM tooling, container security, cloud-native logging and detection |

---

## Beyond Foundations — Onto Hacking

### 🔴 Red Team Resources

| Category | Resource | Notes |
|---|---|---|
| **Labs / Platforms** | [Hack The Box](https://hackthebox.com) | One of the best places to learn, practice, and meet other hackers. Discord is invaluable. |
| | [TryHackMe](https://tryhackme.com) | Best starting point for guided learning. |
| | [VulnHub](https://www.vulnhub.com) | Free vulnerable VMs for local labs. |
| | [PentesterLab](https://pentesterlab.com) | Web app focused. High quality. |
| **Web Application** | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | The gold standard vulnerable web app for learning web hacking. Deploy locally or use hosted version. |
| | [DVWA](https://dvwa.co.uk) | Damn Vulnerable Web Application. Classic. |
| | [PortSwigger Web Security Academy](https://portswigger.net/web-security) | **Free.** Possibly the best web application security training available at any price. Do all of it. |
| **Active Directory** | [TCM — Practical AD](https://academy.tcm-sec.com) | Build it and attack it. Essential. |
| | [HTB Pro Labs](https://hackthebox.com) | Enterprise-scale AD environments to attack. |
| **Privilege Escalation** | [TCM — Linux PrivEsc](https://academy.tcm-sec.com) | |
| | [TCM — Windows PrivEsc](https://academy.tcm-sec.com) | |
| | [GTFOBins](https://gtfobins.github.io) | Unix binary abuse reference. Bookmark this forever. |
| | [LOLBAS](https://lolbas-project.github.io) | Living Off the Land Binaries for Windows. Equally essential. |

### 🔵 Blue Team Resources

| Category | Resource | Notes |
|---|---|---|
| **SOC / Alert Triage** | [LetsDefend](https://letsdefend.io) | SOC simulation. Triage real-world style alerts. |
| | [Blue Team Labs Online](https://blueteamlabs.online) | Excellent defensive focused labs. |
| **DFIR** | [13Cubed (YouTube)](https://www.youtube.com/@13Cubed) | Best DFIR YouTube channel. Watch everything. |
| | [SANS DFIR Posters](https://www.sans.org/posters/) | Free reference posters on Windows forensics artifacts, memory forensics, etc. Print them. |
| | [Eric Zimmerman's Tools](https://ericzimmerman.github.io) | Free Windows forensics tools from a SANS instructor. The standard toolkit. |
| **Memory Forensics** | [The Art of Memory Forensics](https://www.memoryanalysis.net) | The book on memory forensics. |
| | [Volatility Framework](https://www.volatilityfoundation.org) | The industry standard memory forensics framework. Free and open source. |
| **Network Forensics** | [malware-traffic-analysis.net](https://malware-traffic-analysis.net) | PCAPs of real malicious traffic with free tutorials. |
| | [Wireshark](https://wireshark.org) | Learn it deeply. |
| **Threat Intelligence** | [MITRE ATT&CK](https://attack.mitre.org) | The definitive framework for attacker TTPs. Know this framework. |
| | [OpenCTI](https://opencti.io) | Open source threat intelligence platform. |
| **SIEM / Detection** | [Elastic SIEM](https://www.elastic.co/siem) | Free tier available. Build detection rules. |
| | [Splunk Free](https://www.splunk.com/en_us/download.html) | Industry standard SIEM. Free dev license. Learn SPL. |
| **Malware Analysis** | [Any.run](https://any.run) | Interactive malware sandbox. Free tier available. |
| | [VirusTotal](https://virustotal.com) | Always have this open. |
| | [MalwareBazaar](https://bazaar.abuse.ch) | Free malware samples for analysis practice. |

---

## Final Words

This is not a sprint. This is not a six-week cert farm promise. This is a
commitment to genuine, lasting expertise built on a foundation that will serve
you for the entire length of your career.

The people who make it in this field are the ones who stay curious, stay humble,
and never stop learning. The technology will change. The fundamentals will not.

> *"We look special because we master the basics."*

Welcome to the community. It is genuinely one of the best on the planet — full
of people who are willing to help, teach, and share. You are not alone in this.

Now get to work. 🔥

---

*Last updated: 2026 | [DFIRmadness.com](https://dfirmadness.com) |
[@DFIRmadness](https://twitter.com/DFIRmadness)*

##
##

##
##

**This document spawned an entire website. Check it out at: [DFIRmadness.com](https://dfirmadness.com). We have labs, articles and resources like this! See you over there.**

# The Five Pillars of an Information/Cyber Security Professional

## TLD;DR:

"Mastering the basics will make you exceptional."

Master the basics and then specialize to be an invaluable asset to your team.

To start, or level up, a career in Information Security (aka Cyber) Security you need to be proficient in five key areas of technical skills.  You don't have to *master* each one of them, but you need to have a good understanding of them.  Whether you want to go offense or defense you will need to be functional in these five areas:

1. General Computing
2. Computer Networking
3. Scripting and Programming
4. Linux / MacOS
5. Windows

**Note**: I did not come up with the 5 pillars idea on my own.  I *believe* I heard this originally during a conference call with someone from SANS the CyberStart program.  I am not entirely sure of that or if the 5 above are the original 5 laid out.  I *do* remember hearing the 5 areas (or close to these) laid out and it immediately fit into my believe system of mastering the basics to become exceptional.  That idea was hammered home during a good butt chewing delivered during Special Forces training where the instructor told us between flutter kicks and sprints, "We look special because we master the basics".  I have applied to this every complex task I have learned from flying helicopters to hacking and it has served me well.

Don't be scared! While you won't learn it all over night you only need the fundamentals.

If you want to accel in this industry you must also **love** learning.  While it takes a lot of dedication a healthy balance is key.  Make sure your family and friends get time with you, or that you make time to do hobbies you love.

***
## Quick FAQ(ish)

### Wait! Wait! Wait! Where is the hacking!? No where in the list is there hacking or security

Correct.  These are the fundamentals that both defense and offense require!  More focused security paths are added to the second section of this document. Build the foundation and then the house. 

### A Note about Certifaction Pipelines / Schools

The cert farms that tell you A+, Net+, Sec+ and CEH in 6 weeks will get you a career are stealing your money. Certs are important and you will need some most likely, but you DO NOT need 5 in 5 weeks or 5 in 5 months.

### A Note about College Degrees

You do not need a degree in cyber security. You do not need a degree in cyber security.  If you just have to get a degree- get it in Computer Science.  There are sadly an over whelming amount of people with Cyber Security degrees who do not know their way around a keyboard and only know academic theory... they can only talk the talk without being able to walk the walk. Most degree programs do not provide nearly enough hands on fundamentals to set someone up for sucess.

### Typical Career Path

There is no typical career path currently.  Some of the best Cyber Security Pro's were musicians prior! If you have the talent and drive you can work your way in.  That said, a good path would be something like this:

IT Help Desk -> Systems Administrator -> Security Admin -> Specialized Security Role

You can absolutely skip right into security but you will have to study hard and practice a lot of labs that ensure you really have the 5 Pillars well cemented.

### A Note About the Image and Attraction of PenTesting

Before you start:  Perhaps Penetration Testing is all that interests you - or "catching bad guys" is the only thing you want in life.  Remember that learning both sides of the force will benefit you.  The better your understanding of defense the more lethal you can be on offense. **There are probably 10 Blue (defense) jobs to Red (offense).  There are a lot of fun jobs outside of Penetration Testing.**  That said, Penetration testing is a blast and is addicting.  It is also a lot of work and not simply pwning networks and dropping mic's.

Now on to the document...

********

## readme.txt

This document is a path forward for new, and experienced, cyber professionals to obtaining a concrete foundation of knowledge to enable them for success in the industry.  Mastering the basics of each functional area is required to operate on a cyber team (or alone) in a meaningful and effective way.  A lack of fundamentals in any one pillar can quickly render a team member ineffective during dynamic and rapidly evolving situations.  Conversely, no one person on the team should be, or can be, a cyber unicorn.

Ideally, everyone will have a specialty they excel at in addition to a solid baseline in the fundamentals.  It should not be expected that every one completely master each pillar.  The intent is to master the fundamentals.  The fundamentals are simply primal blocks of knowledge of each topic; somewhere between the absolute basics and intermediate.  As an example, a team member should understand: sub-netting, routing, internetworking, OSI model, packet capture, DNS and analysis basics.  This does not mean they need to be Cisco network engineer with a CCNA.

Layout of the document (roughly):

1. Fundamentals and getting started
2. Lab Set Up Advice
3. Security Focused Training and Immersion
4. Security Career Pathways

***
whoami

Twitter: @DFIRmadness

- Veteran
- Former pilot
- Senior Information Security Professional
- Perpetual n00b (always learning)
- Adjunct Professor
- Aspiring SANS Instructor

I have seen folks in multiple industries who would be rockstars if they had a solid mastery of all the basics and not simply pigeon holed into one niche of the field.

***

## Security Tips to Get Started

As you dive into security you should start with good security practices.

1. Don't pirate software.
2. Always have your Admin Account seperate from your daily driver account.
3. Never click a link you didn't ask for.
4. Never use a free VPN (OK - except maybe Proton's).
5. Always check executables and files from others at virustotal.com.
6. Use time based multi-factor on critical accounts like e-mail.
7. Use a password manager and have unique passwords for everything.
8. Use passphrases when able.  Example: 1DeerCloudSubmarine91* [XKCD Password Generator](https://xkpasswd.net/s/).

***

## What You Need (Equipment)

You do not need a $3000 Gaming Laptop or a Desktop with 2 GPU's and 10 TB SSD.  This is completely based on your budget.  You can get away with a $500 laptop if needed. I will explain.

|Level|Explaination|
|---|---|
|Good ($500)|A computer capable of web browsing and reading books. Seriously. The trade off is you will need to pay for web accessible labs versus building a small virtualized environment.|
|Better ($1100ish)|A laptop capable of building a small lab of 2-3 Virtual Machines. Something like an i7, 16 Gigs or RAM and 500 Gigs storage.|
|Best|The sky is the limit.  Something capable of cracking passwords decently (read a mid tier GPU), i9, 32 Gigs, and 1 TB storage.|

**Note**: A GPU is mentioned for password cracking.  You absolutely DO NOT NEED ONE to learn or level up cyber security.  Keep in mind this document is about learning and labs you encounter will be geared towards this anyhow.  You get the same training value in cracking a simple password with your CPU as you do with letting a GPU pound on a hash for 2 weeks.

***

## The Five Pillars (Functional Areas) of Cyber Security

1. General Computing
2. Computer Networking
3. Programming and Scripting
4. Windows
5. Linux

### Fundamentals Breakdown

The following are key skill sets within each pillar.  It is not an exhaustive list.

|Pillar aka Functional Area|Skills|
|---|---|
|**General Computing (Basic Computer Science)**|Hardware Components: <li>CPU<li>RAM<li>SSD/HDD<br>Science:<br><li>Threads<li>Processes<li>Process Trees<li>Memory (RAM)<li>Caching<li>Buffers|
|**Networking**|<li>OSI Model<li>TCP/IP Model<li>TCP vs UDP<li>Packet Analysis<li>Packet Capture<li>Routing<li>DNS<li>ARP<li>Subnets<li>VLANS|
|**Programming and Scripting**|<li>Python<li>Powershell<li>BASH<li>Bonus: C++ or C#|
|**Windows**|<li>Registry (5 Hives)<li>Volume Shadow Copies<li>UAC<li>Memory Paging<li>.msi vs .exe<li>DLLs<li>RIDs<li>SIDs<li>Tokens<li>Network Profiles<li>Server vs. Workstation<li>Commands: <li>Netstat<li>whoami<li>ping<li>ipconfig<li>Powershell Remoting<li>Tools: Sysinternals<li>Process Hacker.|
|**Linux**|<li>Directory Hierarchy<li>sudo accounts<li>/etc/shadow and /etc/passwd<li>ssh<li>telnet<li>ftp<li>Software Repositories<li>Be Familiar with Distributions: Kali, Debian, Ubuntu, CentOS, RedHat<li>Commands: w, find, whoami, which, who, ss, watch, ssh, lsof, ssh-add, top, htop, sudo, nano and vim.|

Yes.  That is a lot.  First, to be good in this industry you will want to be *familiar* with each of these things and beyond.  You will not learn it all over night nor should you try.  Just refer back to this often as a guide.  Be patient. Enjoy the journey.

### Desired Endstate of Each Pillar

The following are goals to shoot for in each area.  If you can meet each of these you will be a competent professional ready to shine at interviews and be an asset to any team you join.

|Pillar aka Functional Area|Skills|
|---|---|
|**General Computing (Basic Computer Science)**|Explain the difference between something being stored in memory vs. something stored on disk. Explain the basics of process injection. Explain the difference between killing a thread and killing a process.|
|**Networking**|Using all 7 layers of the OSI model explain how a piece of information flows from your computer to google.com and back when you type `ping google.com`.<li> Explain what a VLAN is and why they are used.<li>Explain what a subnet is and why they are used.<li>Explain the security protections offered by subnets and VLANs|
|**Programming and Scripting**|Be able to write a basic script to automate a simple task; and be able to read and understand the overall idea of what someone else’s script is attempting to do.|
|**Windows**|Be able to explain the function of the registry, the UAC, and tokens. Be able to maneuver the OS with command line only and look for network connections and their related processes. Possess basic PowerShell (a.k.a PoSh) abilities|
|**Linux**|Be able to explain sudo, shadow and passwd files, user groups and proper installation and maintenance of software (repos).Be able to maneuver the OS with command line only and look for network connections and their related processes.|

*Remember you have to know how things work to exploit them.  You have to know what right looks like to find the gaps in security.*

These goals above are a good measure of when you are ready to deep dive into a specific security path of learning (and of course have fun and sprinkle in security lessons along the way).

### A Note About Certifications

Certifications are a necessity in this industry.  They are far more valuable than a college degree.  That said, don't be a paper tiger where you have a list of certifications and no idea what you are actually doing.  Also- do not fall for the cert farm trap.  These companies that promise you a career is only 5 weeks (or even a few months) away, and that for $20K they will get you there by ram rodding you through A+, Net+, Sec+, and CEH.  They are practically stealing your money.  If you find a place that will teach you essentially the fundamentals laid out here ask to talk to alumni and ensure the instructors are actual industry professionals.

There will be certs listed in this document at times.  For general studies understand that most of the certs mentioned are just great bodies of knowledge to get materials from but the cert itself is not necessary.

#### Certs to Shoot for Early On

GSEC or Sec+.

**NOT A+**.  Friends don't let friends actually get the A+ cert.

**GSEC or Sec+**:  If you live around a lot of Department of Defense facilities that are hiring there is a set of requirements known as [8570](https://www.giac.org/certifications/dodd-8570).  You will basically need GSEC  or Security + for anyone to touch you during the hiring process.  SANS GSEC is the recommended cert here.  It is much more expensive to go through the course but well worth it.

**CEH**:  Certified Ethical Hacker does not make you a penetration tester and doesn't go very far outside of DoD circles.  For the same price you can get the course material for [Penetration Testing with Kali Linux from Offensive Security](https://www.offensive-security.com/pwk-oscp/).  Even if you can't pass the OSCP challenge the material and labs are well worth the $800 or so - certainly *more* so than CEH.

The trick when you are first starting out is to find an employer willing to pay for the certs you need or want.  Get it in writing.  If you can't then understand than the investment of paying for an initial cert or two to get a job will be an investment that will almost certainly have great returns.

***

## Resources:  How Do We Get 'There'?

Now may be a good time to think on *how* you approach learning this mountain of information. [How to learn anything...fast by Josh Kaufman](https://www.youtube.com/watch?v=EtJy69cEOtQ).

### General Approach

- Start free and cheap to see if you like it.  You may find it isn't for you.
- While studying the five functional areas ensure you are getting hands on keyboard and not just your nose in a book.  Do both!  Also - sprinkle in security lessons along with your general studies.  Also, try and rotate through the five continuously so you are leveling up in them all somewhat evenly.  Of course, you can do it in a serial fashion (in order one through five) if you want.  However, these skills are perishable. This means if you go through in order and haven't touched networking in 5 months (or 2 books ago) it is going to be rusty and you will have to relearn it!!!
- Try and have fun!
- Keep an eye out for things you think you may be passionate about!  You will want to specialize later on.

### Recommended Security Focused Resources to go with General Studies

### Hack and Detect: Leveraging the Cyber Kill Chain for Practical Hacking and its Detection via Network Forensics

![Hack and Detect](https://images-na.ssl-images-amazon.com/images/I/51CyN7q7LaL._SX403_BO1,204,203,200_.jpg)

The book to start with: [Hack and Detect](https://www.amazon.com/Learning-Practicing-Leveraging-Practical-Detection/dp/1731254458) ! by Nik Alleyne.  This book can be purchased or viewed free with a Kindle Unlimited account.  This book can't be recommended enough for beginners and experienced folks alike.  It is amazing in its presentation of both offense and defense methodologies with break downs and explanations of each and every command. **This is a great book to sprinkle in along with the 5 pillars studies. Consider it the quick start guide into security.**

### The Cyber Mentor

![The Cyber Mentor](https://yt3.ggpht.com/a/AGF-l7_-iGuCNgJT5TzZNBVoO4V6tCmHv6KOrRMNIA=s288-c-k-c0xffffffff-no-rj-mo)

[The Cyber Mentor](https://www.thecybermentor.com/beginner-linux-for-ethical-hackers): hands down is one of the first people you should start watching as you build your skill sets.  He focuses on Penetration Testing.  He, along with the community he has created in discord etc., will be a great place to find motivation, knowledge and support. Even if you want to go blue side / foreniscs etc. you will need an understanding of how people pentrating networks etc. move through the network and he does a superb job of teaching and explaining.

### General Studies Resources

These resources will have materials for all or multiple pillars.

- [Safari Books Online](https://www.safaribooksonline.com/topics) Free for military members and families
- [Humble Bundle Books](https://www.humblebundle.com/books) They often (every few weeks) have cheap (12 dollars) bundles of books
- [packtpub daily free book give away](https://www.packtpub.com/free-learning) Free IT and Security books given away daily! Some really good ones on occassion.
- <img src = "https://yt3.ggpht.com/a/AGF-l79FABgGifk6OVOrWGLKwdMiysqksJ57Mtp4tg=s288-c-k-c0xffffffff-no-rj-mo" width="50"> [ITPro.tv](https://www.itpro.tv/) is one of **the best** resources out there if you can afford it.  They have tiered pricing models that start as **low as $30 bucks a month!** That is a crazy cheap investment to get into a career with a potential to get you to between 65K and 100K+ annually. This is the first item on the list that you are required to pay for if you choose to use them. They have current, and constantly updated, video series on everything in the five pillars and beyond.  Additionally, they offer virtual labs you can remote into with step by step guides, test question banks and more.  Its an amazing resource.
- [CBT Nuggets](https://www.cbtnuggets.com/) - A direct competitor with ITPro.TV.  They have comparable pricing, virtual labs and *really* good instructional videos.  Their video library does not seem as extensive as that of ITPro.tv.
- [Professor Messer](https://www.professormesser.com/) Another solid instructor that gives A LOT for free.  The community there is also a great resource to connected to.  He sells "notes" for 10 bucks a piece for each cert that are great overviews and resources to keep in your kit bag.
- [Computerphile](https://www.youtube.com/user/Computerphile) an epic youtube channel of PhDs explaining computer science and security concepts.
- [Twitter](https://www.twitter.com) Later there will be a list of people to follow but essentially you can get started with #infosec and #dfir and start a daily ingest of what is going on in the community.  Immerse yourself!

There are so many more amazing people and channels that I will list later in the *Security Specific* Section later.

### Pillar Specific Resources

A Quick Table.  Certs listed here are only pointers to good sources of learning material. In most cases the first few chapters are probably what you need and then specific topic lookups.

|Pillar|Resources|
|---|---|
|General Computing (Basic Computer Science)|<li> A+ Cert videos from [Professor Messer](https://www.professormesser.com/) and [ITPro.tv](https://www.itpro.tv/).  Remember the objectives from above.  You aren't actually getting the cert.<li>[Threads v Processes](https://www.youtube.com/watch?v=O3EyzlZxx3g) video from udacity/Georgia Tech<li>[Professor Messer A+](https://www.professormesser.com/free-a-plus-training/220-901/comptia-220-900-course/)<li>Assosciated Certifications (Good references): A+|
|Networking|<li>[Professor Messer Network+](https://www.professormesser.com/network-plus/n10-007/n10-007-training-course/)<li>[malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) - Collection of PCAPs filled with evil along free tutorials on how to find it with WireShark<li>Any CCENT (Cisco Certified Entry Networking Technician) Materials in ITPro.TV, Safari Books etc. Typically the first few chapters.  Once it gets deep into iOS (Cisco Op System) specific material you’ve hit the limit of the fundamentals<li>[Todd Lammle Internetworking on ITPro](https://app.itpro.tv/course-library/ccent-updated-2016/internetworking/?tagcategory=course-library&tag=legacy) - Todd Lammle gives an amazing internetworking fundamentals course in 15 minutes.  Watch this often.<li>[ITPro 2018 CCENT Course](https://app.itpro.tv/course-library/ccent-updated-2018/overview-ccent2018/?tagcategory=course-library&tag=cisco) - Remember you aren't getting the cert here, but watch the first few hours.<li>[Microsoft Network Fundamentals](https://www.youtube.com/playlist?list=PLsrZV8shpwjMbK0ElithYzT4dGuunT40U) - Concise and to the point!  Excellent videos.<li>Assosciated Certifications (Good references): Net+, CCENT, CCNA<li>[Cisco Packet Tracer](https://www.netacad.com/courses/packet-tracer) - Not only is this software free for personal use but they have some free intro courses there too.|
|Programming and Scripting|<li>[Learn Python.org](https://www.learnpython.org/)<li>[Under The Wire](https://underthewire.tech) - An awesome CTF to learn PowerShell.  Walkthroughs littered through out the internet if you get stuck.<li>[Python for Beginners with Mosh](https://www.youtube.com/watch?v=_uQrJ0TkZlc&t=8500s) - Programming with Mosh. He gets you functional in Python in 6 hours! Looks like a great course.<li>[Code School Season 1](https://www.youtube.com/playlist?list=PLcKpytGyWm9rYbF9URFAjKy2MyWKZe0KS) - Learn to code by following along to make a video game! [Season 2](https://www.youtube.com/watch?v=a_8lfRDls3Y). You don't need to do both seasons or even all of season 1. Remember we are going for the fundamentals.  The more you watch and learn the better, but its not necessary to be a developer to get into Cyber Security.<li>[Microsoft Instructional videos on programming with Python](https://www.youtube.com/playlist?list=PLsrZV8shpwjMbK0ElithYzT4dGuunT40U)<li>[EdX Python Course](https://www.edx.org/learn/python) - Free course from top academic and industry leaders.  A good dive into the science behind it.<li> [Googles Python Course](https://developers.google.com/edu/python/)<li>[Learn Python The Hardway](https://learnpythonthehardway.org/book/)|
|Windows|<li>[ITPro.tv Windows Server Windows 101](https://app.itpro.tv/course-library/server-101/overview-server101/) - GREAT intro course into Windows Servers and Administration. Comes with the assosciated E-Book!<li>[ITPro.tv PoSh Basics](https://app.itpro.tv/course-library/powershell-2017/2017/) - ITPro's take on PowerShell. Great course.<li>[PoSh-Hunter](https://posh-hunter.com/) - A jeopardy style Capture The Flag game to learn PowerShell for InfoSec nerds.<li>[Microsoft Video Series on PowerShell](https://www.youtube.com/playlist?list=PLsrZV8shpwjMXYBmmGodMMQV86xsSz1si) - Another great video series on PowerShell.<li>[Microsoft Virtual Academy Active Directory Course](https://www.youtube.com/watch?v=RPzcxdiyVCM&list=PLsrZV8shpwjOtIz4LFKFQ6uoCt7RowYUZ) - A video series on Active Directory from Microsoft.<li>[Cyber Mentors Active Directory Hacking Lab](https://youtu.be/_OseTyfXr3Q) - Admittedly outside the "general studies" path here but a good one on setting the AD lab up and quick intro, then hacking it.<li> Remember the targeted fundamentals here... you do not need to be an MCSA (Msoft Certified Systems Admin.) to get started.|
|Linux|**Recommended Linux Distro to Start With is: Ubuntu**<li>[Over The Wire Bandit](https://overthewire.org/wargames/bandit/) - The most fun way to learn Linux. This site has many other goodies beyond Bandit games.  Levels 0-10 are a solid intro into linux.<li>[Kali Linux Revealed Free Legit PDF Downlaod](https://kali.training/downloads/Kali-Linux-Revealed-1st-edition.pdf) - An extensive and **FREE** professional book on using linux!<li>[ITPro.tv Becoming A Linux Power User](https://www.itpro.tv/courses/linux/becominglinux-power-user/) - A great video series to level up zero's, beginners and intermediate users.<li> [TCM's Linux Course](https://youtu.be/rZsJieGi8os) - The TCM does it again.  A well thought out course in linux to get you started.<li>[Linux Journey](https://linuxjourney.com/) - An amazing resource! With HTML labs you can do this anywhere on the go.|

***

## Lab Set Ups and Advice

There are two approaches to having a lab environment:

1. Local
2. Remote

### Local Lab

A local lab is built either on your laptop or home built server.  Again, budget dependent.  Building a local lab is actually pretty easy and the process alone will teach you quite a bit.  The world is using a lot of virtualized systems and networks.  Any progress in learning you make here will be a win either way.

To build a local lab on your laptop you will need either of the following (yes there are many more but these are the main staples and finding walk throughs and tutorials are easy) pieces of software:

1. (Paid) VMware Workstation Pro or VMware Fusion for MacOS
2. (Free) VirtualBox

Sadly, you get what you pay for here.  While Virtual Box works fine enough it is certainly no VMware.  You will save hours of troubleshooting and work arounds with VMWare.  It is expensive.  Though its probably a legal gray area, you can find keys for cheap on E-Bay.  The [Cyber Mentors Active Directory Hacking Lab](https://youtu.be/_OseTyfXr3Q) is good crash course on setting up a security lab.  There are a ton of youtube walk throughs and blogs on how to do this.  More will be added here in the future.

#### Local Lab Cyber Range Set-Up Overview

A well outfitted local cyber range that can run on a laptop may look something like this:

|Subnet|Hosts|
|---|---|
|Internal|<li> Windows Domain Controller (D.C.)<li>Windows Client machine on the domain connected to file share on the D.C.<li>Google Rapid Response Server<li>Vulnerable Web Server that in both networks (this allows you to learn to pivot into the network)|
|External|<li> Kali Machine<li>Other Network Connection of the Vulnerable Web Server|

The Kali machine can be moved into the Internal Subnet for "Internal Pentesting" etc.

#### Where to Get Vulnerable VM's

[Vuln Hub](https://www.vulnhub.com/) - A collection of vulnerable virtual machines for your home lab given for free and include a lot of awesome walk-through's to learn from.

[Vuln Hubs Guide to Building A Lab](https://www.vulnhub.com/lab/) - A guided tour on building a home pentesting lab.

### Remote Labs

Another great resource are lab networks set-up and maintained for you to VPN into and go after vulnerable servers or follow along with exercises.

[Hack The Box](https://www.hackthebox.eu/) - One of the most popular pentesting lab environments.  In addition, they have forensics challenges etc with stand alone files.  The community can be very welcoming and educational.  You have to hack your way in to get a membership.  Just follow their directions and have fun!  They have free and paid tier memberships. Paid memberships are something like 12 bucks a month.  Their Discord community is top notch.

[PenTester Academy](https://www.pentesteracademy.com/) - The video quality isn't amazing, but the write-ups, walk throughs and lab environment are great. You can catch great deals on the membership from time to time.  The pricing is between $49 and $69 a month depending on when you catch them.  Well worth it for the [Attack and Defense Labs](https://www.pentesteracademy.com/).

[PenTester Labs](https://pentesterlab.com/) - These are great labs! They are pentesting focused but they have a lot other skills and labs for building your base knowledge.  Once you get a membership you download walkthroughs and an accompanying ISO (a virtual machine image).

***

## Security Specific Studies and InfoSec Immersion

**Start your immersion immediately!**

Once you have a good handle on fundamentals or need some movtivation (or just a break from the more basic 
stuff)

[Vuln Hubs List of Resources](https://www.vulnhub.com/) - A great list of security specific resources!

### Training Companies

[SANS!](https://www.sans.org/) - Hands down the best security training on the planet!  Instructors are highly vetted security professionals with time in the trenches in the area of studies that they teach.  They are pricey. **HINT**: If you can't afford $6-8K a course then look up how to become a [SANS facilitator](https://www.sans.org/work-study/).  By volunteering your time and efforts to help the classes happen you can get a course for about $1500 which is a steal!

A SANS cert is recognized immediately by members of the industry as truly demonstrating that the beholder really understands the topic and can execute the skills assosciated.

### Youtube Channels and Personalities

- [Live Overflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w) - This guy breaks down complex hacking concepts into smaller easier concepts.  He is a good teacher and entertaining.
- [IPPSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) - One *the* best at cracking open boxes on Hack The Box and a great teacher.
- [Cyber Mentor](https://www.youtube.com/channel/UC0ArlFuFYMpEewyRBzdLHiw) - One the best teachers of penetration testing on the internet.  He really gears his videos towards beginners with plenty of new tricks for more experienced folks to pick up.
- [Pauls Security Weekly](https://www.youtube.com/channel/UCg--XBjJ50a9tUhTKXVPiqg) - Security Weekly is one the best podcasts to watch.  The Friday shows have great tech segments. The entire show is informative and entertaining.
- [Brakeing Down Security \(BDS\) Podcast](https://www.youtube.com/channel/UCZFjAqFb4A60M1TMa0t1KXw) - The BDS Podcast is one of the best places to stay up with current security trends.
- [BDS Videos](https://www.youtube.com/playlist?list=PLqJHxwXNn7guMA6hnzex-c12q0eqsIV_K) - Look around here.  There are a ton of free training courses and other gems buried through out.
- [Tyler Hudak Reverse Engineer Training](https://www.youtube.com/watch?v=GYam_nJKr6E) - A great class that is free!  Tyler Hudak is one of the best in the industry and is also a great teacher.
- [NahamSec](https://www.youtube.com/channel/UCCZDt7MuC3Hzs6IH4xODLBw) - A very talented and successful bug bounty hunter and hacker who loves to share techniques with his audiences.

### Twitter Accounts and Personalites

No particular order.

- Cyber Mentor (@thecybermentor)
- Jake Williams (@MalwareJake)
- Derek Root (@\_r00k\_)
- Tyler Hudak (@SecShoggoth)
- Live Overflow (@LiveOverflow)
- Brad from malware traffic (@malware_traffic)
- IPPSec (@ippsec)
- Azeria (@Fox0x01)
- Kody Kinzie (@KodyKinzie)
- Tinker (@TinkerSec)
- Jack Rhysider (@JackRhysider)
- Cyber Gibbons (@cybergibbons)
- Lesley Carhart (@hacks4pancakes)
- Paul Asadoorian (@securityweekly)
- Rob Lee (@robtlee)
- Ed Skoudis (@edskoudis)
- SANS DFIR (@sansforensics)
- MalwareTech (@MalwareTechBlog)
- Malware Unicorn (@malwareunicorn)
- Malware Breakdown (@DynamicAnalysis)
- SANS Institute (@SANSInstitute)
- Ben Sadeghipour (@NahamSec)

There are a ton more I am not recognizing here but this will get you started.  Welcome to the community! And it is a community.  Most hackers out there are some of the best primates on the planet who are willing to help, teach and share.

### Slack Channels

- **Brakeing Down Security**(BDS) - One the best collections of hackers on the planet.  This is easily one of the best places to hang out and chat, learn and share.  You're never alone with the Internet nearby.  You may soon find that your friends and family have little interest in your new passion.

### Discord Channels

- Cyber Mentor
- Hack the Box

### Podcasts

- Darknet Diaries
- Pauls Security Weekly
- Security Now
- Brakeing Down Security
- Brakeing Down Incident Response (It seems dead now but still worth listening to over and over again)
- SANS Internet Storm Center
- The Cyber Wire
- Smashing Security
- Hackable?
- Breach
***
<br>

## Beyond here is in the early stages of fleshing out

1. Career Paths and Guidance
2. Materials for Moving Beyond Foundations (to the Hacking!!)
***

## Career Paths and Guidance

### How to Decide

As you work on the fundamentals you will almost certainly come across various aspects of security that interest you.  All of the following are simply a different flavor of hacker.  They are all vital for any team to function.  A ***general*** lay out of the roles in the security field are (no particular order):

#### Red (Offensive Security):
- **Penetration Tester** - They find and validate vulnerabilities in networks and web applications by demonstrating an attack on that vulnerability.
- **Exploit Developer** - They find vulnerabilities in software and develop exploits to give an attacker unauthorized access to the software or the underlying system.
- **Red Team** - Similar to Penetration Testers except the aim is to not simply validate a vulnerability, but to emulate a realistic threat to that particular environment.  Most likely this means a longer time period for them to operate low and slow to avoid detection and remain in the network for a long(er) period of time.

**Note**: Offensive teams (white hat and black hat alike) are typically made up of specialists.  A rough outline of that looks something like this:

- Entry Team - The initial exploitation to team to get access.
- Developers - The team ready to develop custom malware as needed
- Post Exploitation Team - A collection of folks who are fast at Privilege Escalation and lateral movement.

#### Blue (Defensive Security):
- **Security Operations Center Analyst** - They analyze alerts from intrusion detection sensors and find the root cause of the issue to detect if it is an anomaly or a malicious actor.
- **Security Engineer** - They design and build solutions to support security objectives and requirements.
- **Developer** - Often just another blend of Engineer or even the same title; they automate defesnse systems and things like forensics triage.
- **Forensic Analyst** - 
- **Incident Responder** - 
- **Threat Hunter** - 

### General Bodies of Knowledge Per Role

None of this is "law".

Recommended certs below are merely recommendations and in now way should this list be taken as all inclusive or a rule to be followed.  It also in no way guaruntees successful employment in the respective fields.

**You do not need every cert listed to work in that field!**

For the SANS recommended pathway you should see [their official guidance](https://www.sans.org/cyber-security-career-roadmap).  They have a recommended [road map](https://www.sans.org/cyber-security-skills-roadmap).

### Engineering

|Recommendation|List|
|---|---|
|**CERTIFICATIONS**|<li>SANS Security 401 (GSEC)<li>Linux +|
|**SKILLSETS**|<li>Linux Power User and Administration<li>BASH<li>Python<li>Networking<li>Cloud Technologies (AWS and or Azure)|

### Defensive Forensics and Incident Response (DFIR)

|Recommendation|List|
|---|---|
|**CERTIFICATIONS**|<li>SANS Security 401 (GSEC)<li>SANS Forensics 500 (GCFE)<li>SANS Forensics 508 (GCFA)<li>SNAS Forensics 501 (GCED)<li>SANS Forensics 504 (GCIH)<li>SANS Forensics 503 (GCIA)<li>SEC +<li>CySA +|
|**SKILLSETS**|<li>Linux Power User<li>Linux Security<li>Windows Power User<li>Windows Security<li>Digital Forensics<li>Windows Systems Internals<li>Memory Forenics<li>Networking|

### Threat Hunting

|Recommendation|List|
|---|---|
|**CERTIFICATIONS**|<li>SANS Security 401 (GSEC)<li>SANS Forensics 504 (GCIH)<li>SANS Forensics 500 (GCFE)<li>SANS Forensics 508 (GCFA)<li>SANS Forensics 572 (GNFA)<li>SANS Forensics 503 (GCIA)<li>SEC +<li>CySA +|
|**SKILLSETS**|<li>Linux Power User<li>Linux Security<li>Windows Power User<li>Windows Security<li>Digital Forensics<li>Windows Systems Internals<li>Memory Forenics<li>Threat Intelligence Consumption<li>Security Automation<li>Networking|

### Malware Reverse Engineer

|Recommendation|List|
|---|---|
|**CERTIFICATIONS**|<li>SANS Security 610 (GREM)|
|**SKILLSETS**|<li>Assembly Code<li>Windows Security<li>Linux Security<li>Python<li>Java<li>C<li>HTML|

## Penetration Testing

|Recommendation|List|
|---|---|
|**CERTIFICATIONS**|<li>SANS Security 401 (GSEC)<li>Offensive Security Certified Professional<li>Offesnive Security Certified Engineer<li>SANS Network Penetration Testing SEC560 (GPEN)<li>SANS Web Application Penetration Testing SEC542 (GWAPT)<li>Penetration Test +|
|**SKILLSETS**|<li>Linux Power User<li>Linux Security<li>Windows Security<li>Python<li>BASH<li>Networking<li>Windows Security<li>Windows Sys Internals|

***
## Beyond Foundations and Onto Hacking!

It seems that if you want to become an offensive focused hacker there are a ton of free lab materials and instruction. If you want to focus on the blue team / defensive skillsets it seems to come down to paying a lot of money or reading a lot of books.  E-Learn Security has some Blue Team focused courses that look appealing but I have not personally tested them.

1. Red
2. Blue

### Red

Topic|Links
---|---
Labs / Vulnerable Machines | <li> [Hack The Box](https://www.hackthebox.eu/) - Seriously one of the best places to hang out, learn, have fun, and meet other hackers - oh... and loads of vulnerable machines.  Their discord is invaluable. <li> [Vulnhub](https://www.vulnhub.com/) - Clearing house of vulnerable machines. <li> [Juice Shop](https://www2.owasp.org/www-project-juice-shop/) - One of the greatest projects to teach you Web App Hacking.  The VulnWeb App for your own range along with walkthroughs.<li> [Lesser Known Web Attack lab (LKWA)](https://github.com/weev3/LKWA) <li> [Damn Vulnerable Web App DVWA](https://github.com/ethicalhack3r/DVWA)
##
##
