
c/o 
<br>
https://gist.github.com/subfuzion/08c5d85437d5d4f00e58

<br>
<br>
###################

Common Options
-#, --progress-bar Make curl display a simple progress bar instead of the more informational standard meter.

-b, --cookie <name=data> Supply cookie with request. If no =, then specifies the cookie file to use (see -c).

-c, --cookie-jar <file name> File to save response cookies to.

-d, --data <data> Send specified data in POST request. Details provided below.

-f, --fail Fail silently (don't output HTML error form if returned).

-F, --form <name=content> Submit form data.

-H, --header <header> Headers to supply with request.

-i, --include Include HTTP headers in the output.

-I, --head Fetch headers only.

-k, --insecure Allow insecure connections to succeed.

-L, --location Follow redirects.

-o, --output <file> Write output to . Can use --create-dirs in conjunction with this to create any directories specified in the -o path.

-O, --remote-name Write output to file named like the remote file (only writes to current directory).

-s, --silent Silent (quiet) mode. Use with -S to force it to show errors.

-v, --verbose Provide more information (useful for debugging).

-w, --write-out <format> Make curl display information on stdout after a completed transfer. See man page for more details on available variables. Convenient way to force curl to append a newline to output: -w "\n" (can add to ~/.curlrc).

-X, --request The request method to use.

POST
When sending data via a POST or PUT request, two common formats (specified via the Content-Type header) are:

application/json
application/x-www-form-urlencoded
Many APIs will accept both formats, so if you're using curl at the command line, it can be a bit easier to use the form urlencoded format instead of json because

the json format requires a bunch of extra quoting
curl will send form urlencoded by default, so for json the Content-Type header must be explicitly set
This gist provides examples for using both formats, including how to use sample data files in either format with your curl requests.

curl usage
For sending data with POST and PUT requests, these are common curl options:

request type

-X POST
-X PUT
content type header

-H "Content-Type: application/x-www-form-urlencoded"

-H "Content-Type: application/json"

data

form urlencoded: -d "param1=value1&param2=value2" or -d @data.txt
json: -d '{"key1":"value1", "key2":"value2"}' or -d @data.json
Examples
POST application/x-www-form-urlencoded
application/x-www-form-urlencoded is the default:

curl -d "param1=value1&param2=value2" -X POST http://localhost:3000/data
explicit:

curl -d "param1=value1&param2=value2" -H "Content-Type: application/x-www-form-urlencoded" -X POST http://localhost:3000/data
with a data file

curl -d "@data.txt" -X POST http://localhost:3000/data
POST application/json
curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:3000/data
with a data file

curl -d "@data.json" -X POST http://localhost:3000/data
data.json
{
  "key1":"value1",
  "key2":"value2"
}
data.txt
param1=value1&param2=value2
package.json
{
  "name": "postdemo",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "body-parser": "^1.15.0",
    "express": "^4.13.4"
  }
}
server.js
var app = require('express')();
var bodyParser = require('body-parser');

app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

app.post('/data', function (req, res) {
  console.log(req.body);
  res.end();
});

app.listen(3000);
@espaciomore
espaciomore commented on Feb 3, 2017
very helpful, I used curl to automate some tests written in bash script files

@dianjuar
dianjuar commented on Mar 22, 2017
Thank you... Very instructive.

@rrdennis
rrdennis commented on Apr 18, 2017
Helpful! Many thanks

@Vanshita
Vanshita commented on Jun 8, 2017
Hey.
While running the following command from cmd. It gives the error as '-d' is not recognized as an internal or external command,
operable program or batch file.

Command - >curl -d '{"name": "Abby Mallard", "original_voice_actor": "Joan Cusack", "animated_debut": "Chicken Little"}' -H "Content-Type: application/json" -XPOST http://localhost:9200/disney/character/1

Could anyone help me figure out the mistake?

@pushyamig
pushyamig commented on Jun 22, 2017 • 
IS there a way to do a POST one line at a time from the file that contain array of json events: one JSON per line. I have currently 50K JSON events that i need to post to a service. I felt if curl provide any simple solution with out writing a script for making this happen.

curl -d "@data.json" -X POST http://xyx.org and that data.json contains array of json strings like
{"sensor":"id1","sendTime":"2017-05-07T02:35:16.385Z"}
{"sensor":"id2","sendTime":"2017-05-07T02:35:16.385Z"}

@AaronBaldwin
AaronBaldwin commented on Jun 24, 2017
I struggled with successfully posting JSON to my Express endpoint, and I finally got it working. It was necessary to escape the quotes in the submitted JSON:

curl -d {\"key\":\"value\"} -H "Content-Type: application/json" -X POST "http://localhost:3000/myendpoint"

@yja1
yja1 commented on Jul 9, 2017
http post server_url/add_picture?id=1&img=img1
at the same time upload image data throw payload
I do the server part. I don't konw how to post data also with payload image data. and I don't know how to receive. I use fastcgi do the server part.

@jopek
jopek commented on Aug 15, 2017
@AaronBaldwin you could have also used '' like so: curl -d '{"key":"value"}'

@ghost
ghost commented on Oct 21, 2017
See additional information into free book: https://ec.haxx.se/curl-name.html

@abhishekshukla2017
abhishekshukla2017 commented on Oct 30, 2017
@Vanshita you might have not set the path , set the environment path and try.

@adarshdp
adarshdp commented on Nov 2, 2017
my rest api is not accepting data what i m sending help me out

here code---

"50", "DistrictId" => "26123","taluk_id" => "26103", "taluk_name" => "kattreguppe","Address" => "bangluru", "PhoneNo" => "963258788"); function LogError($error) { $file = fopen("C:/xampp/htdocs/unittest/log/taluk.txt","a"); $t=time(); $t1=date("d-M-Y H:i:s: ", $t); fwrite($file,$t1); fwrite($file,$error); fwrite($file,"\r\n"); fclose($file); } function get_data($url,$returndata) { // $arry= implode(":",($returndata)); //curl_getinfo($ch, CURLINFO_HTTP_CODE); //$data=http_build_query($returndata); $data_json = json_encode($returndata,JSON_PRETTY_PRINT); //$data_json = json_encode(array("customer"=>$data)); LogError($data_json); //var_dump($data_json); //echo $data_json; //$ch = curl_init('http://api.local/rest/users'); /* $json_output = json_encode($returndata, JSON_UNESCAPED_SLASHES); $url = 'http://192.168.1.181/Omps/Views/Mpcs/Services/CreateTaluk/='.urlencode($json_output)'; */ $dat1='{"UnionId":55,"DistrictId":4521,"taluk_id":5252,"taluk_name":adars,"Address":bgnlr,"PhoneNo":9664445}'; $dat="UnionId=55&DistrictId=4521&taluk_id=5252&taluk_name=adars&Address=bgnlr&PhoneNo=9664445"; /* $postData = '';    //create name value pairs seperated by &    foreach($returndata as $key => $value)    {       $postData .= $key . '='.$value.'&';    }    $postData = rtrim($postData, '&'); */ $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $url); curl_setopt($ch,CURLOPT_HTTPHEADER,array ("Accept: application/json",'Content-Type: application/json','Content-Length: ' . strlen($data_json))); //curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json')); curl_setopt($ch, CURLOPT_POST, 1); //$data_json = urlencode(json_encode($returndata)); curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST"); //curl_setopt($ch, CURLOPT_POSTFIELDS,array("customer"=>$data_json)); //curl_setopt($ch, curl_setopt_array,$data_json); curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $response = curl_exec($ch); curl_close($ch); return $response; } // $answer="-*- MPCS Name: ".$UnionId ." MPCS ID: ". $DistrictId." Shift: ".$taluk_id; /* $formdata = array( 'UnionId'=> 1, 'DistrictId'=> 1111, 'taluk_id'=> 3333, 'taluk_name'=> 'abas', 'Address'=> 'bngl', 'PhoneNo'=> 98586598596 ); */ /*$formdata = Array ('UnionId' => 3,'DistrictId' => 260532,'taluk_id' => 26014232,'taluk_name' => 'dvg42','Address' => 'banglore42','PhoneNo' => 96327117652);*/ $formdata = Array ( '[UnionId]' => 3, '[DistrictId]' => 260532, '[taluk_id]'=> 3333, '[taluk_name]'=> 'abas', '[Address]'=> 'bngl', '[PhoneNo]'=> 98586598596 ); //print_r($jsondata); //echo implode(" ",$formdata)."
"; $returned_content = get_data('http://192.168.1.181/Omps/Views/Mpcs/Services/CreateTaluk/',$formdata); echo "",print_r($returned_content,true),""; } } ?>
@adarshdp
adarshdp commented on Nov 2, 2017
failed to update

@cichondev
cichondev commented on Nov 13, 2017
Thanks!

@SakaSaiTrinath
SakaSaiTrinath commented on Nov 22, 2017
Excuse me I am getting the following error, syntaxerror: unexpected token # in json at position 0 at object.parse (native)

I have used the same example for testing and I got this error. Please help me with this.

@Jayhello
Jayhello commented on Nov 29, 2017
thx!!!!

@jaeycyril
jaeycyril commented on Jan 14, 2018
Thanks for this!

@hazratgs
hazratgs commented on Feb 2, 2018
Thanks!

@johnmahugu
johnmahugu commented on Feb 6, 2018
how can i do that in PHP?

@Anilgarapati
Anilgarapati commented on Feb 15, 2018
I need curl syntax for uploading a log file
ex:abc.log

@mgiagante
mgiagante commented on Mar 7, 2018
@pushyamig You can wrap all of your json objects in a single JSON array like so: [ {event1}, {event2}. {even3}] in case your API can accept them that way. If your API endpoint can only accept one at a single time, then you can write a bash script that traverses your json array and throws a curl command for each one of them. Other languages besides bash are more "pretty" for doing this task, like Ruby or Python.

@mgiagante
mgiagante commented on Mar 7, 2018 • 
@Vanshita You probably need to escape your double quotes inside the JSON string with a \ character, so that your shell can know you're using them for the JSON string, and not for your command in the shell (which would close the parameter structure).
Also, notice that you have -XPOST . Try with -X POST.

@mgiagante
mgiagante commented on Mar 7, 2018
@johnmahugu PHP has a curl extension, that allows you to use curl from inside PHP. Not sure if it's the best option, since I'm not a PHP guy https://williamjxj.wordpress.com/2010/11/23/php-curl-library/ .

@wellington1993
wellington1993 commented on Mar 20, 2018
Thanks!

@flyyabelle
flyyabelle commented on Mar 28, 2018
Thanks!

@Gyumeijie
Gyumeijie commented on May 11, 2018
Thanks!

@Mr648
Mr648 commented on Jun 25, 2018
Thanks a lot!

@javieitez
javieitez commented on Jun 27, 2018
Really useful. Thank you!

@ir2pid
ir2pid commented on Jul 17, 2018
how do I post a map as form data

my script:

curl --user ${CIRCLE_TOKEN}: \
    --request POST \
    --form revision=xxx\
    --form config=@config.yml \
    --form notify=false \
    --form build_parameters={key=value} \
        https://circleci.com/api/v1.1/project/bitbucket/project/repo/tree/master

response:

{
"message" : "Invalid build_parameters value: must be a map"
}

@Lamzin
Lamzin commented on Aug 1, 2018
Thanks!

@klfzlyt
klfzlyt commented on Aug 10, 2018
thx

@hendrixroa
hendrixroa commented on Aug 15, 2018
Thanks!

@anasshl
anasshl commented on Aug 22, 2018
hi my qst i a bit different how can i use curl for application/zip to convert the template to pdf

@easywang
easywang commented on Aug 29, 2018 • 
Thanks!

@bkoprivi U can use URLEncode.

@eduardo-marcolino
eduardo-marcolino commented on Aug 31, 2018
thank you for this doc!

@MahendraCandi
MahendraCandi commented on Sep 11, 2018
Wah thank you, but how to write it using jcurl in java code?

@stevedonovan
stevedonovan commented on Sep 13, 2018
Just discovered something that others might also find surprising. If you want to push up some space-significant stuff like YAML, then -d is not your friend. Use --data-binary instead of --data-ascii - otherwise it strips out linefeeds.

@liroforum
liroforum commented on Oct 10, 2018
Thanks,very informative.
I have a curl as below, but how do I access the HOSTNAME(instead of ABCD) of the computer which runs it to pass it to the api?
curl -X PUT "http://localhost:14121/api/SetValue?hostName=ABCD&status=false" -H "accept: application/json" -d "Content-Length: 0"

@jzakrzewski
jzakrzewski commented on Nov 30, 2018
You do not need the "-X POST" in your examples. In fact you shouldn't use it at all. "-d" implies POST request.

@lmoscoted
lmoscoted commented on Dec 16, 2018
Thanks !, it was very useful for debugging on my apache server.

@matheuspaixao
matheuspaixao commented on Dec 26, 2018
@AaronBaldwin Thanks

@Pragna-Tiger
Pragna-Tiger commented on Jan 23, 2019 • 
Is there a way I can post json string itself as string through curl post as follows:
curl --header "Content-Type: application/json" --header "Authorization: Bearer " --request POST --data "{"hp": "[{"hp_col": 5}]","wt": "[{"hp_col": 5}]"}" http://localhost:12800/api/ManualTransmissionService/1.0.0

[{"hp_col": 5}]","wt": "[{"hp_col": 5}] should be identified as a string rather than a json by curl. How do I do it?

@AppleMango23
AppleMango23 commented on Feb 11, 2019
guys i need to use this " POST /ocs/v2.php/apps/dav/api/v1/direct" on my curl how to do that?

@AppleMango23
AppleMango23 commented on Feb 11, 2019
from this website https://docs.nextcloud.com/server/15/developer_manual/client_apis/OCS/index.html?fbclid=IwAR3htVbF8o_roh5-00WZeB_fKjsH9rWwLpmDjkMdTtgSgZbFz56pWNjxXcw#capabilities-api

@Mathieuka
Mathieuka commented on Feb 19, 2019
Thanks is helpfull !

@paigeadelethompson
paigeadelethompson commented on Feb 24, 2019 • 
You want my best curl tricks? you got it

curl -X POST \
-4 \
--random-file /dev/urandom \
--post301 \
--post302 \
--post303 \
--tcp-fastopen \
--tcp-nodelay \
--keepalive \
-s \
--xattr \
-m 15 \
--connect-timeout 2 \
-L \
-w '{\n\t"content_type": "%{content_type}",\n\t"filename_effective": "%{filename_effective}",\n\t"ftp_entry_path": "%{ftp_entry_path}",\n\t"http_code": "%{http_code}",\n\t"http_connect": "%{http_connect}",\n\t"http_version": "%{http_version}",\n\t"local_ip": "%{local_ip}",\n\t"local_port": "%{local_port}",\n\t"num_connects": "%{num_connects}",\n\t"num_redirects": "%{num_redirects}",\n\t"proxy_ssl_verify_result": "%{proxy_ssl_verify_result}",\n\t"redirect_url": "%{redirect_url}",\n\t"remote_ip": "%{remote_ip}",\n\t"remote_port": "%{remote_port}",\n\t"scheme": "%{scheme}",\n\t"size_download": "%{size_download}",\n\t"size_header": "%{size_header}",\n\t"size_request": "%{size_request}",\n\t"size_upload": "%{size_upload}",\n\t"speed_download": "%{speed_download}",\n\t"speed_upload": "%{speed_upload}",\n\t"ssl_verify_result": "%{ssl_verify_result}",\n\t"time_appconnect": "%{time_appconnect}",\n\t"time_connect": "%{time_connect}",\n\t"time_namelookup": "%{time_namelookup}",\n\t"time_pretransfer": "%{time_pretransfer}",\n\t"time_redirect": "%{time_redirect}",\n\t"time_starttransfer": "%{time_starttransfer}",\n\t"time_total": "%{time_total}",\n\t"url_effective": "%{url_effective}"\n}\n' \
--data-urlencode @<(echo -n 'foo=' ; dd if=/dev/urandom bs=1024 count=1 2> /dev/null | xxd -pu | tr -d '\n') \
--cookie-jar /dev/null  https://postman-echo.com/post 2>&1 | jq
result:

{
  "args": {},
  "data": "",
  "files": {},
  "form": {
    "foo=b403ae15001cd5ac80010cfb83288b3026cb82e53d38be4b2975f8ec0b66d81ce7c54a5ac77037ed7dbe895431c957e568e3f62bf2974140b29409dd78f89938d0c78043e50121058b61c942505d906079d00808c264e0889bc69f9777633095aca68ef756d0ba3f89c42986bfe258902d8b29a2a2eafc26d7273f0e75ce6788b34feb5a4dc225e005883cadbcec0434486fa20a8d9646d9db61ea23691ba563c9d85bb7ab1c77f2f94a0b96e7546a9e583397fb8dff5ced7ad140a64af3b20e5958d5f8130267d1d0c09c4db3f355071a6ed3e69af660959b5c589101bfb46344a66f25a5fd276a393c44d49b976f32c70f1c216e4c344d28ffe5277e135f8611eaa172e0e903f393ac7fba0609ea95f26ede71f4534fa502646cc35ae2e3bbf3ce942e5da27f15a16df6a2c647420fe4e89e04b0edf17a7b8ef85dd313505811d61f9d676984d4123f0be6af17ab3e4b2a2abb3d42c2ec5b898d0b6398ee810f33af4f99d2f742fd675b623acbe5a4ee2094cc585ffe9ea60669a1b4b41f324efd7a26b5521b7a920d6b9e09672c627fb5350b6af629354aed91f5fec6b023af623f27c453278dc729658fba50a4b7a9fb6d14c85a086c28543213b07a934c60fbdbfffb2b48196adcdca92c3606a9b43914d067d87bfb23cedeef9d8f8a04639c97efcd7721da3c28a096d88a05a4bcee4d3ca088cf9e1e58624d240bcde64df212c9f028964871be1b6089abfb27c26282a7195ed470dedcb31cd4ef3535c7437b6c2033bcbe865d49afbc9c706a712b5372a76171b502d170db9563d6770a905e235f5ef395581da95ac7c8cf019c8914372ff519067c794ec172c9153e2519b71be93c10cdaf0d332f98b4a3d3cb5fd05814c69fe8d9243aa32d3d8588d87d4512fc5d9f2d76e26417ed52bbfaf416b6cdc041cdf54e064d677558d97e0d4525128c2facc2169453995398d69c24862b9f9b461851191f96048ffc93aa8f773c69f8eca85398cce3169929a7ea1377507c169f2189733de0f1e41b556eadd3de5d480f704f9532f11fb9ee89cc4b87ac3bcc8bf12c1dbfc96c216a1cf472fda4080d415b23563f01dfe8e28b8c9b689cbf17dc5062296810f9f873857163343d9dc3e6fc2686bf0f1665fee24e1a4f5db8a71c95de61d0f928ad6af142d8cf481cf55fc68ff7ef4342a8643311b708d5ec3d3d4b6ae767dbedae36c7968c2a801b8a8300a2377452e4df1b574d3f004be60fd4ea7bd5fc240362ff38dae21b81c3707317e8f26182fcf6b10347d85fc4b8a098c57d4fa984640c10da5c18f8a45d926b073012cf398b6beca988b0333b1ba30320d33aeae9e187ac2fe9c76100a945235ba70cae1a8228c92f5bc015a130c504ad1c5d334bc238810d4ca05a8a4e1092022fbca1d284ccfaccafcf978a50e04c761848040f9b1c088f9b": ""
  },
  "headers": {
    "x-forwarded-proto": "https",
    "host": "postman-echo.com",
    "content-length": "2054",
    "accept": "*/*",
    "content-type": "application/x-www-form-urlencoded",
    "user-agent": "curl/7.60.0",
    "x-forwarded-port": "443"
  },
  "json": {
    "foo=b403ae15001cd5ac80010cfb83288b3026cb82e53d38be4b2975f8ec0b66d81ce7c54a5ac77037ed7dbe895431c957e568e3f62bf2974140b29409dd78f89938d0c78043e50121058b61c942505d906079d00808c264e0889bc69f9777633095aca68ef756d0ba3f89c42986bfe258902d8b29a2a2eafc26d7273f0e75ce6788b34feb5a4dc225e005883cadbcec0434486fa20a8d9646d9db61ea23691ba563c9d85bb7ab1c77f2f94a0b96e7546a9e583397fb8dff5ced7ad140a64af3b20e5958d5f8130267d1d0c09c4db3f355071a6ed3e69af660959b5c589101bfb46344a66f25a5fd276a393c44d49b976f32c70f1c216e4c344d28ffe5277e135f8611eaa172e0e903f393ac7fba0609ea95f26ede71f4534fa502646cc35ae2e3bbf3ce942e5da27f15a16df6a2c647420fe4e89e04b0edf17a7b8ef85dd313505811d61f9d676984d4123f0be6af17ab3e4b2a2abb3d42c2ec5b898d0b6398ee810f33af4f99d2f742fd675b623acbe5a4ee2094cc585ffe9ea60669a1b4b41f324efd7a26b5521b7a920d6b9e09672c627fb5350b6af629354aed91f5fec6b023af623f27c453278dc729658fba50a4b7a9fb6d14c85a086c28543213b07a934c60fbdbfffb2b48196adcdca92c3606a9b43914d067d87bfb23cedeef9d8f8a04639c97efcd7721da3c28a096d88a05a4bcee4d3ca088cf9e1e58624d240bcde64df212c9f028964871be1b6089abfb27c26282a7195ed470dedcb31cd4ef3535c7437b6c2033bcbe865d49afbc9c706a712b5372a76171b502d170db9563d6770a905e235f5ef395581da95ac7c8cf019c8914372ff519067c794ec172c9153e2519b71be93c10cdaf0d332f98b4a3d3cb5fd05814c69fe8d9243aa32d3d8588d87d4512fc5d9f2d76e26417ed52bbfaf416b6cdc041cdf54e064d677558d97e0d4525128c2facc2169453995398d69c24862b9f9b461851191f96048ffc93aa8f773c69f8eca85398cce3169929a7ea1377507c169f2189733de0f1e41b556eadd3de5d480f704f9532f11fb9ee89cc4b87ac3bcc8bf12c1dbfc96c216a1cf472fda4080d415b23563f01dfe8e28b8c9b689cbf17dc5062296810f9f873857163343d9dc3e6fc2686bf0f1665fee24e1a4f5db8a71c95de61d0f928ad6af142d8cf481cf55fc68ff7ef4342a8643311b708d5ec3d3d4b6ae767dbedae36c7968c2a801b8a8300a2377452e4df1b574d3f004be60fd4ea7bd5fc240362ff38dae21b81c3707317e8f26182fcf6b10347d85fc4b8a098c57d4fa984640c10da5c18f8a45d926b073012cf398b6beca988b0333b1ba30320d33aeae9e187ac2fe9c76100a945235ba70cae1a8228c92f5bc015a130c504ad1c5d334bc238810d4ca05a8a4e1092022fbca1d284ccfaccafcf978a50e04c761848040f9b1c088f9b": ""
  },
  "url": "https://postman-echo.com/post"
}
{
  "content_type": "application/json; charset=utf-8",
  "filename_effective": "",
  "ftp_entry_path": "",
  "http_code": "200",
  "http_connect": "000",
  "http_version": "1.1",
  "local_ip": "",
  "local_port": "0",
  "num_connects": "1",
  "num_redirects": "0",
  "proxy_ssl_verify_result": "0",
  "redirect_url": "",
  "remote_ip": "",
  "remote_port": "0",
  "scheme": "HTTPS",
  "size_download": "4412",
  "size_header": "380",
  "size_request": "178",
  "size_upload": "2054",
  "speed_download": "3454.000",
  "speed_upload": "1608.000",
  "ssl_verify_result": "0",
  "time_appconnect": "0.770223",
  "time_connect": "0.256651",
  "time_namelookup": "0.004238",
  "time_pretransfer": "0.770268",
  "time_redirect": "0.000000",
  "time_starttransfer": "1.022882",
  "time_total": "1.277659",
  "url_effective": "https://postman-echo.com/post"
}
Good luck! and just to be clear --random-file /dev/urandom you probably shouldn't use that one unless you need to dispatch lots of curl requests really fast and can't gather enough entropy from the default; generally speaking this should be faster because urandom is non-blocking but is less pseudo random than /dev/random

Also *, here is a really dirty (but sometimes useful) trick I threw together that uses -T which would normally be for a PUT but I'm overriding it to POST with -X POST:
curl -X POST \
-4 \
--random-file /dev/urandom \
--post301 \
--post302 \
--post303 \
--tcp-fastopen \
--tcp-nodelay \
--keepalive \
-s \
--xattr \
-m 15 \
--connect-timeout 2 \
-L \
-w '{\n\t"content_type": "%{content_type}",\n\t"filename_effective": "%{filename_effective}",\n\t"ftp_entry_path": "%{ftp_entry_path}",\n\t"http_code": "%{http_code}",\n\t"http_connect": "%{http_connect}",\n\t"http_version": "%{http_version}",\n\t"local_ip": "%{local_ip}",\n\t"local_port": "%{local_port}",\n\t"num_connects": "%{num_connects}",\n\t"num_redirects": "%{num_redirects}",\n\t"proxy_ssl_verify_result": "%{proxy_ssl_verify_result}",\n\t"redirect_url": "%{redirect_url}",\n\t"remote_ip": "%{remote_ip}",\n\t"remote_port": "%{remote_port}",\n\t"scheme": "%{scheme}",\n\t"size_download": "%{size_download}",\n\t"size_header": "%{size_header}",\n\t"size_request": "%{size_request}",\n\t"size_upload": "%{size_upload}",\n\t"speed_download": "%{speed_download}",\n\t"speed_upload": "%{speed_upload}",\n\t"ssl_verify_result": "%{ssl_verify_result}",\n\t"time_appconnect": "%{time_appconnect}",\n\t"time_connect": "%{time_connect}",\n\t"time_namelookup": "%{time_namelookup}",\n\t"time_pretransfer": "%{time_pretransfer}",\n\t"time_redirect": "%{time_redirect}",\n\t"time_starttransfer": "%{time_starttransfer}",\n\t"time_total": "%{time_total}",\n\t"url_effective": "%{url_effective}"\n}\n' \
-T <(echo -n '["' ; dd if=/dev/urandom bs=1024 count=1 2> /dev/null | xxd -pu | tr -d '\n' ; echo -n '"]') \
--cookie-jar /dev/null  -H "Content-Type: application/json" https://postman-echo.com/post 2>&1 | jq
The advantage of using -T is that you can stream read which in the case of a file descriptor is immensely useful if you don't know the length, (whereas --data and --data @file will read the entire contents of the file into a buffer in memory before the POST is sent, but -T reads however many bytes the internal read callback expects and asynchronously begins writing, hence why this is a very dirty hack.) You can also override with -H "Expect: " -H "Content-Length: " and some HTTP servers will accept it however for various reasons they shouldn't. I don't know if this behavior was ever actually intended, I should probably e-mail the haxx list one of these days and find out for sure.

Result:

{
  "args": {},
  "data": [
    "80e0082f8e67a4d056ef3482e1b68a9fd72a6f6ec72c171de3911fb90f5fb1c78c7d8bc11f6d540b4b27d8e5c28757b0f7b95fc618df1c893eb357ce4255e2101e55203afccaf945ff67b5a09cbcbd417eb8b87e4d3a98f89a52c818d0fe436499b9e81ca40c7b01be0fedee4c82a17beb7c62ac153aa88fbc4fe095e505ecb395bfca0b7b60c372bab139424a4ffbd6f8cc1fb7132c77cca3c3d3837b749934294762069cbda5cf8d7b96ab7dbad296eac26b3145cd939dc1eb73656dadad16e3ca483e02ee521351a37cf88172da900b6c94d5f5e95013c112c9e7c8fa4b2d6001e76210d6a70b19f07c21e86847264f3cbe3a21369910f10765a80a840929302a2d48a2429a3ac5ef101bd29c1005682b9ac903d4846329d6b71fb203e618bd1dc01ce2262b1eac26f29f5417f479d7a4e815971c781f77c630fae01ea9f7ef24b85011a62c3609abeb3570ba10e425b987c32279355d229300bdad6567bf733b92b11d9ebe53fd1a5264850f014fa9985baf09582ce5cdf7b7fff53dda9992008f0d4ef5ac7f1118478fbf6b42ad6f50a05ace4142efb5006f70d6ae98726a108976f2bdc27700f153bd1d633bb9aeceab947d18b4d79bee180a7589d0688af8046cb6ae579360cbbe09b4a0a4e0b8fbb3731589ba9acb71d176bfda15e5c97bb1621b8e83dcd02353f4452345f92528315d9d786b9888b565eae9c7d9d1da6f8a9d37b8a038cd6cd4351d4ff58bbe6d649f1b2f6bb1b871a3cabed68bf38f0dbe1141b795f1d673955ebd1fa44cb63908ae428c1a1aefc4a60a2ca95841dd3d8e09a1a6a5111c3720d6e69e9dcc452549228e333a2c30cd5462378a934c1b2bddb99fb612558212433a446da2753f777e9047a96b1e0f7824ca76c811a7f4a57961f35deeed1ee1e498f06254b6ae506234f7405b57d97867a278578b9c35b0cdca9c6b85e6798c473e7764d82290487acad6a0b68b606ee4f3be69cbced20d8f898881dcf2d62f0ea2ce333aa7b459d4b5222ba129683e4509a8c80510969ae827f467979bf65980439aec060e4dcf1869985cd18a1b28616b8318c2f2073c57d478dc10affbaab13ca95fa904216bc290acde76c52b71163574237c9f61632d74d63f4a0d43495ffc46a25d75c53303c0cc1cd5ef7b3d54a31ec96fcd2043dd468446076843a591df53f279fb4c4c6aabb90f1fddc5a728ab5a43fd43cf7752879f7ee508cb40ef84d678805c0b426153b967eb12c86b19265592da898d9ccaea02f0de371b29806d1ffcb7341073458adcb97a6d99bfa1e381bc81ce6c04f595f9239742fc9bc5138f47141e396ed4efe0b948ff5b4234b60f3767c5b3898db65672d7a2eb9734f6ce32d50996911a49110150f6f4f671fcec2d7b1a2f472022285b293e2f5ec30e8304a6668916706984d9f6a8fd25f4813df4b238"                                               
  ],
  "files": {},
  "form": {},
  "headers": {
    "x-forwarded-proto": "https",
    "host": "postman-echo.com",
    "content-length": "2052",
    "accept": "*/*",
    "content-type": "application/json",
    "user-agent": "curl/7.60.0",
    "x-forwarded-port": "443"
  },
  "json": [
    "80e0082f8e67a4d056ef3482e1b68a9fd72a6f6ec72c171de3911fb90f5fb1c78c7d8bc11f6d540b4b27d8e5c28757b0f7b95fc618df1c893eb357ce4255e2101e55203afccaf945ff67b5a09cbcbd417eb8b87e4d3a98f89a52c818d0fe436499b9e81ca40c7b01be0fedee4c82a17beb7c62ac153aa88fbc4fe095e505ecb395bfca0b7b60c372bab139424a4ffbd6f8cc1fb7132c77cca3c3d3837b749934294762069cbda5cf8d7b96ab7dbad296eac26b3145cd939dc1eb73656dadad16e3ca483e02ee521351a37cf88172da900b6c94d5f5e95013c112c9e7c8fa4b2d6001e76210d6a70b19f07c21e86847264f3cbe3a21369910f10765a80a840929302a2d48a2429a3ac5ef101bd29c1005682b9ac903d4846329d6b71fb203e618bd1dc01ce2262b1eac26f29f5417f479d7a4e815971c781f77c630fae01ea9f7ef24b85011a62c3609abeb3570ba10e425b987c32279355d229300bdad6567bf733b92b11d9ebe53fd1a5264850f014fa9985baf09582ce5cdf7b7fff53dda9992008f0d4ef5ac7f1118478fbf6b42ad6f50a05ace4142efb5006f70d6ae98726a108976f2bdc27700f153bd1d633bb9aeceab947d18b4d79bee180a7589d0688af8046cb6ae579360cbbe09b4a0a4e0b8fbb3731589ba9acb71d176bfda15e5c97bb1621b8e83dcd02353f4452345f92528315d9d786b9888b565eae9c7d9d1da6f8a9d37b8a038cd6cd4351d4ff58bbe6d649f1b2f6bb1b871a3cabed68bf38f0dbe1141b795f1d673955ebd1fa44cb63908ae428c1a1aefc4a60a2ca95841dd3d8e09a1a6a5111c3720d6e69e9dcc452549228e333a2c30cd5462378a934c1b2bddb99fb612558212433a446da2753f777e9047a96b1e0f7824ca76c811a7f4a57961f35deeed1ee1e498f06254b6ae506234f7405b57d97867a278578b9c35b0cdca9c6b85e6798c473e7764d82290487acad6a0b68b606ee4f3be69cbced20d8f898881dcf2d62f0ea2ce333aa7b459d4b5222ba129683e4509a8c80510969ae827f467979bf65980439aec060e4dcf1869985cd18a1b28616b8318c2f2073c57d478dc10affbaab13ca95fa904216bc290acde76c52b71163574237c9f61632d74d63f4a0d43495ffc46a25d75c53303c0cc1cd5ef7b3d54a31ec96fcd2043dd468446076843a591df53f279fb4c4c6aabb90f1fddc5a728ab5a43fd43cf7752879f7ee508cb40ef84d678805c0b426153b967eb12c86b19265592da898d9ccaea02f0de371b29806d1ffcb7341073458adcb97a6d99bfa1e381bc81ce6c04f595f9239742fc9bc5138f47141e396ed4efe0b948ff5b4234b60f3767c5b3898db65672d7a2eb9734f6ce32d50996911a49110150f6f4f671fcec2d7b1a2f472022285b293e2f5ec30e8304a6668916706984d9f6a8fd25f4813df4b238"                                               
  ],
  "url": "https://postman-echo.com/post"
}
{
  "content_type": "application/json; charset=utf-8",
  "filename_effective": "",
  "ftp_entry_path": "",
  "http_code": "200",
  "http_connect": "000",
  "http_version": "1.1",
  "local_ip": "",
  "local_port": "0",
  "num_connects": "1",
  "num_redirects": "0",
  "proxy_ssl_verify_result": "0",
  "redirect_url": "",
  "remote_ip": "",
  "remote_port": "0",
  "scheme": "HTTPS",
  "size_download": "4381",
  "size_header": "382",
  "size_request": "167",
  "size_upload": "2064",
  "speed_download": "3341.000",
  "speed_upload": "1574.000",
  "ssl_verify_result": "0",
  "time_appconnect": "0.790392",
  "time_connect": "0.262910",
  "time_namelookup": "0.004183",
  "time_pretransfer": "0.790463",
  "time_redirect": "0.000000",
  "time_starttransfer": "1.049153",
  "time_total": "1.311899",
  "url_effective": "https://postman-echo.com/post"
}
@DarthShmev
DarthShmev commented on Jun 1, 2019
Thanks, very helpful.

@jerrylau91
jerrylau91 commented on Jun 16, 2019
really helpful summary

@dinhdv-java
dinhdv-java commented on Jun 21, 2019
Thanks, very helpful.

@ghost
ghost commented on Jul 5, 2019
Thank you for sharing information with us

@DwordPtr
DwordPtr commented on Jul 11, 2019
👍

@weber77
weber77 commented on Jul 15, 2019
please how can i pass a double array in json using curl to test a REST api

here is a code i tried using

curl -d'{"num1" : "{ [1, 2, 3,48], [2,5,4,5]}"} ' -H"Content-Type: application/json" -X POST http://localhost:8080/process

@corfanous
corfanous commented on Jul 19, 2019
Great

@init6tech
init6tech commented on Aug 20, 2019
i am trying to give as a variable with -d option but its not working. {"$user"}. can anyone help me on this

@DwordPtr
DwordPtr commented on Aug 20, 2019
Try “${user}”

@init6tech
init6tech commented on Aug 21, 2019
Try “${user}”

Hi DwordPtr,

Thanks for your response. Partially issue got resolved but still I stuck with the problem. I am giving arguments from outside while executing shell script. In below lines, i am giving organization value at the time of executing script. organization is getting created if i give argument for organization but if you see in second line, data.json also contains $organization value. but arguments/variables which I am passing at the time of script is not passing to data.jason file and it is taking value as "$organization".

curl -X POST $get_url/organizations -H 'Accept: application/json' -H "Authorization: AccessToken $token" -H 'Content-Type: application/json' -d "{"description": "customer", "name": "$organization"
curl -d "@data.json" -X POST $get_url/role-grants/organization-grants

Error: exception.TenantAccessDeniedException","message" The organization '/$organization' is inaccessible for the user organization '/'.","statusCode":403

@neeraj2681
neeraj2681 commented on Aug 22, 2019
Thanks for the short and crispy tutorial!

@anandzhang
anandzhang commented on Nov 6, 2019
Thank you very much for your explanation.

@cuncdev
cuncdev commented on Dec 3, 2019
I grabbed it in a glance ! Thank you for this !

@rjpcasalino
rjpcasalino commented on Dec 12, 2019
@stevedonovan thanks for the tip on --data-binary vs -d (was about to smash my head against the table) 👍

@HammzaHM
HammzaHM commented on Dec 18, 2019 • 
@subfuzion Thanks a lot it is helpful 👍

@thomaslevesque
thomaslevesque commented on Jun 3, 2020
Thanks!

@WIttyJudge
WIttyJudge commented on Jun 6, 2020
Thank you 😎

@sergnio
sergnio commented on Aug 13, 2020
Thank you so much :)

In your second Application/JSON example, you're missing a header

POST application/json
curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:3000/data
with a data file

curl -d "@data.json" -H "Content-Type: application/json" -X POST http://localhost:3000/data
