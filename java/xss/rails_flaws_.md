

##
#
https://chefsecure.com/blog/i-found-xss-security-flaws-in-rails-heres-what-happened
#
##



Ruby on Rails is a web framework used for quickly building web applications with minimal setup and configuration.

Although it's isn't so trendy anymore, it's stable and reliable in most cases so it's still used by a lot of companies like Github, Shopify, Airbnb, Soundcloud and even here at Chef Secure.

Here's the problem
The code I showed you earlier is a function used by developers to escape untrusted data for safe use in JavaScript strings.

You can use it like this:

string = '<%= j untrusted_data %>'
or like this

string = '<%= escape_javascript untrusted_data %>'
And it'll stop untrusted data from running malicious code in XSS attacks.

As you know, JavaScript strings can be created with single or double quotes. However when ES6 was introduced in 2015, it added a new way to create strings using what's called template literals.

'string1'
"string2"
`string3`
The difference: template literals allow you to build strings while including variables and expressions inside.

Walking through the vulnerability
Here's an example. Let's say you want to show a user's online status using their name and a getStatus function that takes in their id so the end result looks like this:

Jesse is Online

The old way would be to add the different pieces of the string together.

'<%= j user.name %> is ' + getStatus(<%= user.id %>)
The new way with template literals allows you to combine these pieces together inside a single string:

`<%= j user.name %> is #{getStatus(<%= user.id %>)}`
So how do we exploit this?

As I go over in the Attacks inside JavaScript recipe in my XSS course, the most common way attackers achieve XSS in JavaScript is by breaking out of strings in order to get into the execution context - the place where your code gets run.

Now, in contrast to HTML where you can have invalid syntax without much consequence, JavaScript is very picky and will stop working with even the smallest error, so you need to make sure you end up with valid JavaScript after your injection.

The pattern I present in the recipe is simple:

start with your payload (alert())
surround it with matching string characters
and finally add a plus in between each part
stringChar+alert()+stringChar
This allows you to break out of JS strings without errors – just like adding in a new variable.

Do you see what's missing now?

The first attack
The escaping doesn't account for backticks being used to create strings via template literals. In this case, this means we can run our exploit using the exact same pattern with backticks for the string characters.

`+alert()+`
Okay, so let's add protection from backticks.

JS_ESCAPE_MAP = {
  "'"    => "\\'",
  '"'    => '\\"',
  '`'    => '\\`',
  ...

def escape_javascript(javascript)
  # replace every unsafe character with safe version
  return javascript.gsub(/(\\|\r\n|[\n\r"'`])/u, JS_ESCAPE_MAP)
end
There's still another problem
It turns out that the same benefit offered by template literals to combine expressions inside strings, also allows attackers to execute malicious code without even having to break out of the string!

So to launch an attack this time, we'd just surround our payload with the ${} interpolation piece and we don't have to worry about any extra parts.

${alert()}
And now the second fix is to escape the $ character to stop this.

JS_ESCAPE_MAP = {
  "'"    => "\\'",
  '"'    => '\\"',
  '`'    => '\\`',
  '$'    => '\\$',
  ...

def escape_javascript(javascript)
  # replace every unsafe character with safe version
  return javascript.gsub(/(\\|\r\n|[\n\r"'`$])/u, JS_ESCAPE_MAP)
end
We were warned
It turns out this scenario was already discussed 8 years ago.

After the Rails patch was released, James Kettle, Director of Research at PortSwigger, sent me a message on Twitter linking to a discussion on adding template literals to JavaScript where Gareth Heyes warns about the holes that will open up as a result.

Gareth warns:

... this will introduce a new class of DOM based XSS attacks since developers in their infinite wisdom will use this feature to place user input inside ...
Read the full discussion here.
