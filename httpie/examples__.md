##
#
https://gist.github.com/jeszy75/a435d5f16402636b7dc3d66bb09ea3d8
#
##

# Pass parameters with json data.

```
http http://localhost:8085/query  \
	events:='["cache.hit", "cache.miss"]' \
	select:='["$count"]' \
	group:='"$event"'

http post http://localhost:8085/events \
	event=cache.hit \
	data:='{"file_type":"html", "file_name":"foobar.html"}'
	
Test API hapinness

 http post 'http://localhost:8000/user/login' \
       email=thiago.zilli@gmail.com \
       password=123mudar

 http --auth-type=jwt \
      --auth=$(cat token.txt): \
      -f \
      post \
      'http://localhost:8000/upload' label='pdf of google sample' \
      file@/home/zilli/google.pdf


Using HTTPie in the Commmand Line
=================================

Installation
------------

Installing with [Miniconda](https://docs.conda.io/en/latest/miniconda.html) (Linux, macOS, Windows):

```
conda config --add channels conda-forge
conda install httpie
```

Checking Availability
---------------------

```
http
http --version
```

Help
----

```
http --help
man http
```

Documentation: <https://httpie.io/docs/cli>

Basic Use
---------

Website: <http://ip-api.com/>

```
http http://ip-api.com/json
http http://ip-api.com/json -v
http http://ip-api.com/json --download
http http://ip-api.com/json -d
http http://ip-api.com/json --print Hh
http ip-api.com/json
```

Redirection
-----------

### Example (1)

Website: <http://www.w3.org/>

```
http http://w3.org
http http://w3.org --follow -d -o w3.html -v
http http://w3.org -F -d -o w3.html -v
```

### Example (2)

URL shortening service: <https://is.gd/>

```
http https://is.gd/create.php?format=simple\&url=https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Evolution_of_HTTP -d -o shorturl.txt
cat shorturl.txt
cat shorturl.txt | xargs http --print=h HEAD | grep -i ^Location
```

Content Negotiation
-------------------

### Example (1): The same content in several different languages

Website: <http://www.gnu.org/>

```
http http://www.gnu.org/ Accept-Language:de -p Hh
http http://www.gnu.org/ Accept-Language:de -p Hh -d -o gnu.de.html
http http://www.gnu.org/ Accept-Language:fr -p Hh -d -o gnu.fr.html
```

### Example (2): Redirecting to the mobile version of a website

Website: <https://www.youtube.com/>

```
http https://www.youtube.com/ "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
```
See: <https://www.whatismybrowser.com/guides/the-latest-user-agent/>

### Example (3): The same content in several different formats

See: <https://www.dbpedia.org/>

```
http https://dbpedia.org/resource/Grumpy_Cat -v
http https://dbpedia.org/resource/Grumpy_Cat Accept:text/html -d -o Grumpy_Cat.html -v
http https://dbpedia.org/resource/Grumpy_Cat Accept:application/json -v
http https://dbpedia.org/resource/Grumpy_Cat Accept:application/json -d -v
```

Resume an Interrupted Transfer
------------------------------

See: <https://download.bbbike.org/osm/bbbike/Budapest/>

Press <kbd>CTRL</kbd> + <kbd>C</kbd> to interrupt transfer:

```
http https://download.bbbike.org/osm/bbbike/Budapest/Budapest.osm.gz -d
```

Resume transfer with:

```
http https://download.bbbike.org/osm/bbbike/Budapest/Budapest.osm.gz -d -c -o Budapest.osm.gz
```

Range Requests
--------------

See: <https://www.gnu.org/licenses/gpl-3.0.txt>

The first 100 bytes:

```
http https://www.gnu.org/licenses/gpl-3.0.txt Range:bytes=0-99 -d -v
```

The last 100 bytes:

```
http https://www.gnu.org/licenses/gpl-3.0.txt Accept-Encoding: Range:bytes=-100 -d -v
```

The first and last 100 bytes:

```
http https://www.gnu.org/licenses/gpl-3.0.txt Accept-Encoding: Range:bytes=0-99,-100 -v
```

Submitting Form Data
--------------------

### Introduction

Website: <https://httpbin.org/>

Available options:

* GET method:
  ```
  http http://httpbin.org/get string==bazinga number==42 -v
  http http://httpbin.org/get "string==Hello, World!" number==42 -v
  ```

* POST method with the [`application/x-www-form-urlencoded`](https://www.iana.org/assignments/media-types/application/x-www-form-urlencoded) media type:
  ```
  http --form http://httpbin.org/post string=bazinga number=42 -v
  ```

* POST method with the [`multipart/form-data`](https://www.iana.org/assignments/media-types/multipart/form-data) media type:
  ```
  http --multipart http://httpbin.org/post string=bazinga number=42 -v
  ```

### Example (1): GET

Website: <https://blackwells.co.uk/>

```
http https://blackwells.co.uk/bookshop/search?keyword=sherlock+holmes\&pubDateFrom=2022\&pubDateTo=2023 -d -o search.html -v
http https://blackwells.co.uk/bookshop/search keyword==sherlock+holmes pubDateFrom==2022 pubDateTo==2023 -d -o search.html -v
```

### Example (2): POST

Website: <https://www.base64encode.org/>

```
http -f POST https://www.base64encode.org/ input="Hello, world!" charset=UTF-8 separator=lf -d -o output.html -v
```

### Example (3): GET

Website: <https://validator.nu/>

```
http https://validator.nu/ doc==https://www.w3.org/ -d -o output.html -v
```

### Example (4): POST

See: <https://validator.nu/#file>

```
http https://www.w3.org/ -d -o index.html
http -f POST https://validator.nu/ file@index.html -d -o output.html -v
```

Consuming Web Services
----------------------

### Example (1): wttr.in

See: <https://wttr.in/>, <https://github.com/chubin/wttr.in>

```
http http://wttr.in
http http://wttr.in/:help
http http://wttr.in/London
http http://wttr.in/New+York
http http://wttr.in/~Tower+Bridge
http http://wttr.in/~Mount+Everest
http http://wttr.in/ Accept-Language:en
http http://wttr.in/ Accept-Language:de
http http://wttr.in?lang=hu
http http://wttr.in?lang=en
http http://wttr.in?lang=de
http http://hu.wttr.in
http http://de.wttr.in
http http://wttr.in/?format=1
http http://wttr.in/?format=2
http http://wttr.in/?format=3
http http://wttr.in/?format=4
http http://wttr.in/?format=j1
http http://wttr.in/Budapest?format=v2
http http://v2.wttr.in/Budapest
http http://wttr.in/Moon
```

### Example (2): Nu Html Checker

See: <https://validator.nu/> <https://github.com/validator/validator/wiki/Service-%C2%BB-Common-params>

```
http https://validator.nu/ doc==https://whatwg.org/ out==json -v
http https://validator.nu/ doc==https://whatwg.org/ out==xml -v
http https://validator.nu/ doc==https://www.w3.org/ out==xml -v
http https://validator.nu/ doc==https://www.w3.org/ out==xml level==error -v
http https://whatwg.org/ -d -o whatwg.html
http POST https://validator.nu/?out=xml @whatwg.html "Content-type:text/html;charset=utf-8" -v
```

### Example (3): file sharing (temp.sh)

See: <https://temp.sh/>

```
echo "Hello, World!" > hello.txt
http --multipart https://temp.sh/upload file@hello.txt -v
```

Cookies
-------

See: <https://httpie.io/docs/cli/sessions>

```
rm -f youtube.json
http --session=./youtube.json https://www.youtube.com/ -d -v
less youtube.json
http --session=./youtube.json https://www.youtube.com/watch?v=pTBjHjRhx_Y -d -v
```

Authentication
--------------

### Example (1): API key

Website: [Rebrickable API](https://rebrickable.com/api/)

Swagger UI for the API: <https://rebrickable.com/api/v3/swagger/>

Using the API requires an API key the can be generated [here](https://rebrickable.com/users/jeszy/settings/#api) (requires login).

```
http https://rebrickable.com/api/v3/lego/sets/60386-1/ "Authorization: key <your-api-key>" -v
http https://rebrickable.com/api/v3/lego/sets/60386-1/minifigs/ "Authorization: key <your-api-key>" -v
http https://rebrickable.com/api/v3/lego/sets/60386-1/parts/ "Authorization: key <your-api-key>" -v
```

### Example (2): Basic Authentication

```
http https://api.github.com/user -v
http https://api.github.com/user -v -a <username>
```

See:
* <https://docs.github.com/en/rest>
* <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens>

JSON
----

See: <http://httpbin.org/#/Anything>, <https://httpie.io/docs/cli/json>

### Example (1)

```
http http://httpbin.org/anything name="Tim Berners-Lee" email=cos@timbl.com url=https://www.w3.org/People/Berners-Lee/ -v
```

### Example (2)

```
http http://httpbin.org/anything title="The Big Bang Theory" year:=2007 seasons:=12 ended:=true genres:='["comedy", "romance"]' -v
http http://httpbin.org/anything title="The Big Bang Theory" year:=2007 seasons:=12 ended:=true genres[]=comedy genres[]=romance -v
http http://httpbin.org/anything title="The Big Bang Theory" year:=2007 seasons:=12 ended:=true genres[1]=romance genres[0]=comedy -v
http http://httpbin.org/anything title="The Big Bang Theory" year:=2007 cast:='{"Leonard Hofstadter": "Johnny Galecki", "Sheldon Cooper": "Jim Parsons", "Penny": "Kaley Cuoco", "Howard Wolowitz": "Simon Helberg", "Raj Koothrappali": "Kunal Nayyar", "Bernadette Rostenkowski": "Melissa Rauch", "Amy Farrah Fowler": "Mayim Bialik"}' -v
http http://httpbin.org/anything title="The Big Bang Theory" year:=2007 cast["Leonard Hofstadter"]="Johnny Galecki" cast["Sheldon Cooper"]="Jim Parsons" cast[Penny]="Kaley Cuoco" cast["Howard Wolowitz"]="Simon Helberg" cast["Raj Koothrappali"]="Kunal Nayyar" cast["Bernadette Rostenkowski"]="Melissa Rauch" cast["Amy Farrah Fowler"]="Mayim Bialik" -v
```
