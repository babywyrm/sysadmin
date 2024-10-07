

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
