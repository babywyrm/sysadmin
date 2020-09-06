https://gist.github.com/joecampo/848178ab5c18aada0eabjoecampo/fail2ban.md


++++++++++++++++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++++++++++++++++


Last active 26 days ago • Report abuse
38
8
 Code
 Revisions 19
 Stars 38
 Forks 8
<script src="https://gist.github.com/joecampo/848178ab5c18aada0eab.js"></script>
fail2ban – stop HTTP(S) route abuse/brute forcing
fail2ban.md
If you're not familiar: What is fail2ban? fail2ban is an awesome linux service/monitor that scans log files (e.g. auth.log for SSH) for potentially malicious behavior. Once fail2ban is tripped it will ban users for a specified duration by adding rules to Iptables. If you're unfamiliar with fail2ban Chris Fidao has a wonderful (& free!) series about security including setting up fail2ban here.

Recently Laravel released a new feature in 5.1 to throttle authentication attempts by simply adding a trait to your authentication controller. The Laravel throttle trait uses the inputted username, and IP address to throttle attempts. I love seeing this added to a framework out of the box, but what about some of our other apps not built on Laravel? Like a WordPress login? Or even an open API etc.? Ultimately, we’re trying to simply eliminate those that are abusing a HTTP/HTTPS route, or some other service, (in this example, brute forcing into a login). We're not trying to ban user John who simply can’t remember his password. Instead of/or in addition to adding code to the appliation layer to handle this logic to keep out major brute force/abuse attempts, we can leverage fail2ban to create custom filters for specific routes in our Apache/Nginx access log to ban those IP addresses from the server at the Iptables level. For this example & setup, I will be using Ubuntu & Apache.

If you don’t have fail2ban installed already, you can install it quickly using aptitude:

sudo apt-get install -y fail2ban

You can check to see if fail2ban is running:

sudo service fail2ban status

You can also check what “jails”/filters you have running by running:

sudo fail2ban-client status

Fail2ban is located in /etc/fail2ban. In this folder, you should see a jail.conf and you may see a jail.local. jail.conf is the main configuration file for all of the filters used in fail2ban. You should not make any changes to the jail.conf file. jail.local is your configuration that overrides everything located in jail.conf. If you do not have a jail.local, you should instead copy your jail.conf to jail.local and make any additions/edits to your local file. This will mitigate any issues when upgrading fail2ban in the future.

First, let’s create our new definition. All filter definitions are located in the filter.d directory. We’ll need to create a new filter within this directory.

sudo touch weblogin.conf

Now we can open it in our editor of choice:

sudo nano weblogin.conf

For this example, we’re going to be setting a filter that will scan our apache access log for POST requests to /login. If you open your apache access log /var/log/apache2/access.log you’ll be able to see all of the requests and be able to find the request that you’d like to scan for.

Example:

10.1.1.1 - - [02/Sep/2015:11:27:56 -0400] "POST /login HTTP/1.1"

In your auth.conf file you’ve created we’ll setup our definition:

[Definition]
failregex   = ^<HOST> .* "POST /login
ignoreregex =
So we’re looking for the IP address and the POST to /login. You could also set specific ignoreregex here if you wanted to do so as well. That’s it for this file. Now that we’ve created the definition we’ll need to specify the log paths, and enable the filter. Let’s navigate back to /etc/fail2ban and open our jail.local file.

sudo nano jail.local

At the end of the file we’ll want to add a new jail for the new definition we’ve created.

[weblogin]
enabled  = true
filter   = weblogin
action   = iptables-multiport[name=NoAuthFailures, port="http,https"]
logpath  = /var/log/apache2/access.log
banTime  = 3600
findtime = 60
maxRetry = 20
The new entry should match the name of your new definition conf file (in this case weblogin.conf). So we're saying that if there are (20) POST requests in (1) minute to /login we're going to ban the user from access HTTP/HTTPS for (1) hour.

enabled - Whether the filter should be turned on or not.
filter - The name of the configuration file you placed in filters.d
action - The action we want to take, in this case, ban the user from http, https traffic.
logpath - The log path we want fail2ban to scan. In this case, the Apache access log, but this could very well be your Nginx access log.
banTime - The amount of time we want to ban the user from (in seconds)
findtime - The duration of time we want fail2ban to look back in the log to see if the user should be banned. (in seconds)
maxRetry - The amount of times that host should be able to make their attempt before the filter is triggered.
Once we've configured out settings all we'll need to do is restart the fail2ban service:

sudo service fail2ban restart

We can check to see if the service is running back by checking the status again

sudo fail2ban-client status

You'll likely see this output and you'll be able to see that your jail is listed. In this case auth.

Status
|- Number of jail:      2
`- Jail list:           weblogin, ssh
You can test your filter to make sure that it is working properly. Personally, I will tail the fail2ban log: sudo tail -f /var/log/fail2ban.log. Once you trigger the filter you'll see yourself get banned and eventually, unbanned. I usually test the filter with small durations to make sure I have it correctly. :)

2015-09-03 22:19:12,215 fail2ban.actions: WARNING [weblogin] Ban 10.1.1.1
2015-09-03 22:20:12,321 fail2ban.actions: WARNING [weblogin] Unban 10.1.1.1
And we're done! An incredibly simple way to secure a specific HTTP route from being flooded, or brute forced that requires no additional code within your project. As you can see, you can definitely apply this to anything that has a log file that fail2ban can scan.

Joe
