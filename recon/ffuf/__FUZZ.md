# Web fuzzers review

## Intro

This is a December 2020 web fuzzing tools review made by myself. I have measured times, CPU usage and RAM consumption in three different lists, 10K, 100K and 400K lines and putting each tool with three different sets of threads: 40, 100 and 400 threads.&#x20;

Why? Because I have been a ffuf user since version 0.9 (13 Apr 2019) and recently I thought that maybe it was time to review the rest of the tools.

{% hint style="info" %}
This is not intended to be a serious investigation, a technical paper, or anything like that, just a series of tests that I have done for fun. The results shown are my opinion and if at any time you do not like them or you don't agree, you can stop reading or explain to me how I could have done it better :)
{% endhint %}

All the results of my runs and tests are posted [here](https://docs.google.com/spreadsheets/d/14eFVYoYxMOTZ1tI2jADnvNw\_0S6HHJMQXcp5NelhtY0/edit?usp=sharing), it has three sheets (info, performance and features).&#x20;

{% embed url="https://docs.google.com/spreadsheets/d/14eFVYoYxMOTZ1tI2jADnvNw_0S6HHJMQXcp5NelhtY0/edit?usp=sharing" %}

## Tools

Small summary of each tool with the features and results that I got. This section not follows any special order.

### [wfuzz](https://github.com/xmendez/wfuzz)

* Author: [@x4vi\_mendez](https://twitter.com/x4vi\_mendez)
* Language: Python

GitHub's first release 2014, it's like a tank for web fuzzing, it has a lot of (really a lot) customizations and does almost everything very well. Everybody knows it, he was the best until Golang came.

#### Pros

* Lot of customization.
* Maybe most versatile.

#### Cons

* RAM eater.
* High CPU usage even with sort lists.
* Slow.

### [ffuf](https://github.com/ffuf/ffuf)

* Author: [@joohoi](https://twitter.com/joohoi)
* Language: Go

GitHub's first release Nov 2018. For me, it has become the best, it is fast, versatile, many options and does not give problems.

#### Pros

* Fast.
* Multiple options.
* Low resource usage.

#### Cons

* Fancy/non-relevant features like:
  * Pause/resume.
  * ETA.
* Ugly recursion output.
* Only errors count, to check them you must run again with -debug file flag.

### [feroxbuster](https://github.com/epi052/feroxbuster)

* Author: [@epi052](https://twitter.com/epi052)
* Language: Rust

GitHub's first release Oct 2020. It's the youngest in the list and I really wanted to try it because it looks great and comes with some features that I didn't see in other tools.

#### Pros

* Response link extractor.
* Pause and resume.
* Low CPU usage.

#### Cons

* Tool has crashed in some tests.
* Feels buggy.
* RAM eater.
* No FUZZ keyword.
* No rate/time limits.

### [gobuster](https://github.com/OJ/gobuster)

* Author: [@OJ](https://twitter.com/TheColonial)
* Language: Go

GitHub's first release 2015. For me, it was the predecessor of fuff, I used it on OSCP exam, and it took me a while to get rid of it.

#### Pros

* Really fast.
* Low CPU and RAM.
* S3 enum.
* Patterns usage.

#### Cons

* No recursion.
* No colors.
* No filters.
* Lack of features.

### [rustbuster](https://github.com/phra/rustbuster)

* Author: [@phra](https://twitter.com/phraaaaaaa)
* Language: Rust

GitHub's first release May 2019. I got to this one because I read about it on the feroxbuster page and I found it very interesting.

#### Pros

* The fastest.
* Best in CPU and RAM.
* IIS Shortname scanner

#### Cons

* No recursion.
* No colors.
* The one with the least features.
* Last commit sept 2019, maybe abandoned.
* Sometimes crashes with many threads.

### [dirsearch](https://github.com/maurosoria/dirsearch)

* Author: [@maurosoria](https://twitter.com/\_maurosoria)
* Language: Python

GitHub's first release Jul 2014. It was the first fuzzing tool I used, it comes with custom wordlist, pretty output and a lot of options.

#### Pros

* Prettiest output imo.
* Quality options by default.
* Easy of use, recommended for noobs.
* Wordlists mutation.

#### Cons

* The slowest.
* No FUZZ keyword.

## Results

### Time

1. rustbuster
2. ffuf
3. gobuster
4. feroxbuster
5. wfuzz
6. dirsearch

### CPU

1. feroxbuster
2. dirsearch
3. gobuster
4. ffuf
5. rustbuster
6. wfuzz

### RAM

1. gobuster
2. rustbuster
3. ffuf
4. dirsearch
5. feroxbuster
6. wfuzz

### Features

1. ffuf
2. wfuzz
3. dirsearch
4. feroxbuster
5. gobuster
6. rustbuster

### General

1. ffuf
2. gobuster
3. feroxbuster
4. rustbuster
5. dirsearch
6. wfuzz

## Final thoughts

I will continue using ffuf because it seems that it's the tool with the best balance between functionalities and performance. I was very surprised by Rust and I really want Feroxbuster to continue growing and become a worthy rival for ffuf and finally it seems that the fathers of fuzzing tools are left behind, the world advances!


# 
# Directory fuzzing

## Theory

While Crawling allows testers to build the indexed architecture of website, this technique can't find directories and files that are not referenced. Directory fuzzing (a.k.a. directory bruteforcing) is a technique that can find some of those "hidden" paths. Dictionaries of common paths are used to request the web app for each path until exhaustion of the list. This technique relies on the attacker using a dictionnary/wordlist. A request is made for every line of the wordlist to differentiate pages that exist and pages that don't

## Practice

### Fuzzing tools

Tools like [dirb](http://dirb.sourceforge.net/) (C), [dirbuster](https://sourceforge.net/projects/dirbuster/) (Java), [gobuster](https://github.com/OJ/gobuster) (Go), [wfuzz](https://github.com/xmendez/wfuzz) (Python), [ffuf](https://github.com/ffuf/ffuf) (Go) and [feroxbuster](https://github.com/epi052/feroxbuster) (Rust) can do directory fuzzing/bruteforcing. Burp Suite can do it too. Depending on the web application, one will be better suited than another and additional options will be needed.

```bash
gobuster dir --useragent "PENTEST" --wordlist "/path/to/wordlist.txt" --url $URL
```

```bash
wfuzz --hc 404,403 -H "User-Agent: PENTEST" -c -z file,"/path/to/wordlist.txt" $URL/FUZZ
```

[ffuf](https://github.com/ffuf/ffuf) (Go) and [feroxbuster](https://github.com/epi052/feroxbuster) (Rust) are two awesome alternatives that can do recursive fuzzing unlike [gobuster](https://github.com/OJ/gobuster) (Go) and [wfuzz](https://github.com/xmendez/wfuzz) (Python) mentioned above.

```bash
ffuf -H "User-Agent: PENTEST" -c -w "/path/to/wordlist.txt" -maxtime-job 60 -recursion -recursion-depth 2 -u $URL/FUZZ
```

```bash
feroxbuster -H "User-Agent: PENTEST" -w "/path/to/wordlist.txt" -u http://192.168.10.10/
```

{% hint style="warning" %}
Directory fuzzing needs to be slowed down when testing production instances as it could lead to an unintended denial of service, especially when using [feroxbuster](https://github.com/epi052/feroxbuster), a tool known for it's high speed.
{% endhint %}

### Wordlists

In order to fuzz more accurately, there are many dictionaries adapted for many situations, most of which can be downloaded from SecLists. SecLists can be installed (`apt install seclists` or downloaded directly from [the GitHub repo](https://github.com/danielmiessler/SecLists)).

The ultimate combo is [ffuf](https://github.com/ffuf/ffuf) + [fzf](https://github.com/junegunn/fzf) + [seclists](https://github.com/danielmiessler/SecLists).

{% hint style="success" %}
In the following command, [fzf](https://github.com/junegunn/fzf) is used to print a file fuzzer prompt allowing the user to quickly choose the perfect wordlist for content discovery.

```bash
feroxbuster -H "User-Agent: PENTEST" -w `fzf-wordlists` -u http://192.168.10.10/
```

In this case, `fzf-wordlists` is an alias to the following command using fzf and find to fuzz wordlists from specific directories.

```bash
find /usr/share/seclists /usr/share/wordlists /usr/share/dirbuster /usr/share/wfuzz /usr/share/dirb -type f | fzf
```
{% endhint %}
