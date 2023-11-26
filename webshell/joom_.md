

##
#
https://anshildev.medium.com/wordpress-and-joomla-reverse-shells-f76dcdbc0339
#
https://github.com/babywyrm/Joomla-webshell-plugin
#
##

WORDPRESS AND JOOMLA REVERSE SHELLS
Anshildev
Anshildev

·
Follow

4 min read
·
Dec 11, 2022




This short tutorial will explain how to get a reverse shell on two common web applications: WordPress and Joomla.

Both of these require authentication so it is assumed that credentials were already gained via another vulnerability such as LFI and a reverse shell on Tom cat, another common web app

Both WordPress and Joomla reverse shells are obtained in the same way. Since both allow the authenticated user to execute PHP code, we can write in a reverse shell and activate it. WordPress uses plugins to do this and Joomla uses what it calls ‘templates’. As an aside, I’m very familiar with WordPress (this site uses it) and I’ve seen a lot of other sites using WordPress, although admittedly I haven’t seen Joomla before starting on HackTheBox. Maybe I just never noticed the websites that use it? Anyway, we will begin with getting a reverse shell on WordPress.

WordPress
First, navigate to <url>/wp-admin/ for the default WordPress login page. You should be greeted with the following:


figure 1: WordPress admin login page
Log in with your credentials and you will be taken to the main dashboard.


Figure 2: Admin dashboard
Now click on ‘Plugins’ on the left-hand side and click ‘Installed Plugins’. There is a default plugin called ‘Hello-Dolly’, but you can use any plugin as long as you can execute it somehow. Click ‘Edit’ underneath the plugin.


figure 3: plugins page
We can now see the PHP code for the plugin we clicked on. All we need to do now is add in some PHP code to start a reverse shell.


figure 4: PHP code for Plugin
copy and paste the PHP reverse shell one-liner from your cheatsheet and put in your IP details and choose a port number. On your own machine, open a netcast listener.


Figure 5: Reverse shell (on the left, highlighted) and listener (on the right)
Next, click ‘Update File’ in the bottom left. It will say ‘File edited successfully’ at the top. Now go back to the plugins page and click ‘Activate’ to start the plugin.


Figure 6 : Reverse shell
and that's it, We have our reverse shell. Unfortunately only on www-data, so privilege's escalation will be required from her.

Joomla
Next up is joomla! we’re going to do the same thing on Joomla except inside a ‘template’, not a plugin.

Head to <Url>/administrator/ and login using your credentials.


Figure 7: JOOMLA Login PAGE
Now you’ll be on the admin panel (note it says ‘An error has Occurred’ on mine , I’m using the Enterprise box from HackTheBox to demonstrate this. Not sure why this has an error, but we’re logged in nonetheless).


Figure 9: Templates
You’ll now see a list of templates. Pick one to customize it.


Figure 10: Example template
To start our reverse shell, we need to edit one of the PHP files and then save and run this template. We’ll edit index.php. Add the reverse shell code to the index.php file and start your netcat listener.


Figure 11: Reverse shell code
Click the green ‘Save’ button. The shell may start now, but if not, click ‘Template Preview’.


Figure 12: Reverse shell
And now we have a reverse shell in Joomla. As we can see, both WordPress and Joomla have basically the exact same method for getting a reverse shell. Both of these examples were using a one-liner reverse shell, but pentestmonkey also has a more complex and perhaps better reverse shell tool for PHP which can be found

here



Sign up to discover human stories that deepen your understanding of the world.
Free
Distraction-free reading. No ads.

Organize your knowledge with lists and highlights.

Tell your story. Find your audience.

Sign up for free
Membership
Access the best member-only stories.

Support independent authors.

Listen to audio narrations.

Read offline.

Join the Partner Program and earn for your writing.

Try for $5/month



