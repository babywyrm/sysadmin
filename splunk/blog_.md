
##
#
https://donkeycoder.medium.com/my-best-splunk-queries-part-i-67b4b0a2ee96
#
##


We use Splunk day to day, and having a perfect query for every occasion helps us big time with monitoring, debugging, issue tracking, especially that Google Analytics has a hard position for upcoming iOS changes. We use Apache logs for index, and track custom events hitting a self hosted tracking pixel with different parameters.
How can I get stats by screen size? How to get statistics by combination of two fields?

index=httpdlogs file=”tracking.gif” platform=phone | eval size=screenWidth. “x” .screenHeight | stats count by size | where count > 10000

So this search would look good in a pie chart as well, however you prefer it. The prerequisits being that we log the screenWidth and screenHeight. We also provide a shortcut for phone platform, and we also remove noise by setting minimum count of results. As you can see from the slides this example has decent iPhone5/5C/5S (320x568) usage compared to iPhone XS (414x896). For all iOS resolutions, look here. The 360x640 size is the most common Android phone size, coming from various Samsung and other devices.
How to get stats based on Browser/Chrome version? How to use regexp to get version stats?

index=httpdlogs file=”tracking.gif” | rex field=useragent “Chrome/(?<chromeversion>[0–9.]+)” | timechart count by chromeversion span=24h

In this search we use a Regular expression for getting the version of Chrome, and storing it to field `chromeversion`, and then using the count by day to display charts. This is very good if you want to track if a new Chrome release is affecting your KPIs or not. The regular expression itself is simple, just looks for 0.0.0 format, with any length of numbers having dots between, but it needs to come after “Chrome”. The great bit here from splunk is that it allows you to save the regex match as a field.
How to get iOS versions statistics from user agent in splunk?

Similarly to above query, we can do a regexp search for iphone os version, and see 13.5 being popular at 74% today across our userbase.

index=httpdlogs file=”tracking.gif” | rex field=useragent “iPhone OS (?<iosver>\w+)” | chart count by iosver

How to show ratio or percentage between two charts? How to eval evaluated fields?
I’ve made this chart to highlight some issues with backend, and help tracking it down to the time. As it was correlating to user load, it was really helpful to show the errors as a percentage of total app usage.

index=httpdlogs file=”tracking.gif” (event=”token-error” OR event=”AppInit”) 
| timechart span=1h count(eval(searchmatch(“token-error”))) as tokenError, count(eval(searchmatch(“AppInit”))) as AppInit 
| eval PercentOfTokenErrors = (tokenError/AppInit)*100 
| timechart span=1h per_hour(PercentOfTokenErrors)

A lot of things going on here, so lets see. We want to display ratio of ”token-error” and ”AppInit”, so we need to search for any of those 2, so the evals will run faster. Then in timechart we actually evaluate both as a searchmatch, and count them, also saving them as new fields, so in the next pipe we can use them in a different eval. The timechart luckily does the bucketing, so that step is allright. Then the next pipe will evaluate the percentage, so we can see how much of the application inits will cause the token error. Then we can display the PercentOfTokenErrors as per_hour basis, and get the nice chart above, and to make it a constant reminder for the team to fix, we can put it on a dashboard. :)
How to get count of unique values in search?

index=httpdlogs event=AppInit | stats dc(userId)

This is a simple one, but not too straightforward, just use | stats dc(filedName)
How to display load time by platform? How to display average statistics over time?

index=httpdlogs file="tracking.gif” event=loaded | timechart avg(elapsedTime) span=24h by platform

This is a simple search again, we are looking for the ‘loaded’ events, and display their average by platform. It’s needed to log the elapsedTime from the client in the tracking parameters.
How to compare stats to previous days

index=httpdlogs file="tracking.gif” event=eventImLookingFor | timechart count span=1h | timewrap d

This is a very nice way to compare performance of KPIs between releases, and making sure everything is behaving as expected. Just search for the event, and use timewrap. Also notice that the last hour is incomplete.

Thanks for listening, if you liked this conent, please clap a few! :)
Support independent authors and access the best of Medium.
Authors earn when you read member-only stories.
Or sign up for free
