Decoding PDF Injection
Urshila Ravindran
Urshila Ravindran

##
#
https://medium.com/@urshilaravindran/pdf-injection-in-simple-words-8c399f92593c
#
##




PDF injection was listed down in the top 10 web application hacking techniques of 2020 and still it appears to be one of the most underrated vulnerability.


PDF Injection
This article talks about PDF injection from scratch to the execution of XSS and SSRF via PDF injection.

What is a PDF?

PDF stands for “portable document format”. This format is used when you need to save files that cannot be modified but still need to be easily shared and printed. Today, almost everyone has a version of Adobe Reader or other program on their computer that can read a PDF file.

What is the structure of a PDF?

The PDF is majorly divided into 3 parts : -

Objects
xref table, also known as “cross reference table”
Trailer
1. OBJECTS
The objects in a PDF basically consist of the contents of the document and these objects are present inside the file body. Objects can be data related to the images, fonts, annotations or any other such data.


PDF Structure (Objects)
In the above image, you can see that this is how objects look like in an actual PDF code. Firstly, we have the name of the object which is “1” in this instance. The second number is “0” which is the revision number. It is not used that much as it always seems to be zero in most of the PDF formats. Next, we have the “obj” part which basically tells us that this whole thing is an object. It actually indicates the start of an object.

The pointy brackets (<<>>) denote that this object 1 is of dictionary type. Dictionary is a commonly used datatype in the PDF files and it contains a list of key and value pairs.

Followed by this, there is a dictionary key denoted by /Pages, and 2 0 R is the value of the dictionary key. Here, R indicates that this is a reference number so it is looking for the second object in this particular instance. That is why, the first number here is 2. The following number is 0 which is the revision number. The /Pages dictionary basically allows you to define the number of pages in the PDF.

And in this instance, it is using a reference to the second object which will define the information being displayed in the PDF file.

2. CROSS REFERENCE TABLE (xref table)
A cross reference table consists of links to all the objects in a PDF file. It can be used to navigate to other pages or content in the file. So, whenever someone updates the PDF, it automatically gets updated in the xref table.


PDF Structure (xref table & trailer)
The above image depicts the xref table which begins with an xref keyword. Here, the first object in the PDF file starts at 10th position. The startxref keyword basically tells you where in the document, the xref table begins so in this particular instance, the xref table begins from the position number 413.

3. TRAILER
The trailer in a PDF code starts with a trailer keyword. It basically contains the links to the cross reference tables. And in the end, we have an end of file (EOF) marker to mark the end of the PDF file.

So, this is the overall structure of a PDF document!

PROCESS OF PARSING IN A PDF FILE

Parsing process inside a PDF file
The injection point will most likely occur in the objects itself and then the payload will be executed inside the object when the document is rendered.

How to inject an input inside a PDF?
Server-side PDF generation is everywhere. It exists almost everywhere like its in invoices, receipts, e-tickets, payslips, boarding passes and the list is endless. Hence, there are plenty of opportunities to get the user input inside a PDF document.

If you imagine a PDF injection as an XSS injection and imagine you are injecting the parenthesis, this is very similar to what happens when you are injecting inside a PDF code.

Like javascript, you have to always ensure that the syntax is valid. You have to repair the parenthesis before the injection as well as after the injection


PDF file code
In the above code, you can see that an object is defined which is object number “4” with a specified length, 50. Here, BT stands for beginning of text. Followed by this, the font and the font size is defined and then the actual text or user input is present (in this instance, it is “Hello World!”). An injection can take place here but the problem we have here is that, even if we can inject a new object, the xref table will not be updated. Hence, the injected input will not be rendered when we open the PDF file. So in this scenario, the PDF injection is not possible.


PDF File code
The annotations in a PDF code looks like the one shown in the above picture. These annotations basically allow you to define a link anywhere in the document. They have an option to create a rectangle, for where you want the page to be clickable. It is done with the help of a “Rect” dictionary. Here, a URI is defined using the URI dictionary key and you can perform the injection within the parenthesis as the value of the URI dictionary key.

So, this is what makes PDF Injection possible!

PDF GENERATION LIBRARIES ALREADY VULNERABLE TO PDF INJECTION
The following are some of the libraries already vulnerable to PDF injection : -

PDF-Lib
jsPDF
WeasyPrint
Foxit PDF Library
Microsoft Windows PDF Library
XSS & SSRF THROUGH PDF INJECTION
Let us consider a code of the PDF generated by a PDF generation library already vulnerable to PDF Injection. It was found that they do not escape the parenthesis/backslashes inside the annotations.

We can insert the newly defined annotations inside the code by first breaking out of the existing annotation and then creating a new annotation. To define the rectangular coordinates, choose specific rectangle coordinates to determine the section of the document that should be clickable.


XSS payload inside the PDF code
In the above image, you can see that a /Parent dictionary is defined to enable the Javascript execution and along with this, a button is created. Next, we have to break out of the parenthesis and then break out of the dictionary using >> before starting a new annotation dictionary.

The /S dictionary makes the annotation, javascript-based and the /JS dictionary is where the javascript is stored. The actual javascript payload (“alert(1)”) is present inside the parenthesis.


Collaborator URL in the submitForm function
In addition to this, you can append a submitForm function to make a request to an external URL or in the above case, you can use a Burp Collaborator URL.


XSS & SSRF execution in a PDF File
Finally, you will receive the alert(1) response on the browser along with an HTTP and DNS request on the Burp Collaborator. So, this is the case of a Blind SSRF which can be performed in PDFs.

METHODOLOGY OF TESTING THE PDF GENERATION LIBRARIES
The methodology to test the PDF generation libraries to check whether they are vulnerable to PDF Injection or not, consists of 3 main steps, Identification of PDF injection vulnerability in the library, Construction of Payload and then Exploitation.

Firstly, you need to identify if you can inject the parenthesis or the backslashes.
Once you have identified that the library is vulnerable, then you can try and find a site that uses this library. Followed by this, construct a PDF containing the injection that has a callback by either calling “alert(1)” or a callback by using the submitForm function which would send a POST request to an external URL.
Now, this can be useful in blind scenarios where you don’t know the structure or content of the PDF but you can still cause an injection, also on applications that do not support Javascript, you can use the submitForm action and do a callback.

3. Now, that you have identified that your PDF is now rendered successfully with your injected payload and you have got a callback, in this case, you can exploit it by stealing the contents of the PDF using the submitForm actions.

REMEDIATIONS TO AVOID THE RISK OF PDF INJECTION
Considering the library level, you should always ensure that the parenthesis are escaped correctly in the annotations, URLs and the text streams. The PDF libraries should always escape the PDF strings, that includes parenthesis and backslashes.

If we consider the web application level, it should always be ensured that the validation of the content is being performed, before being inserted into the PDF, in order to ensure that there are no unwanted Javascript or submitForm actions.

REFERENCES
https://portswigger.net/research/portable-data-exfiltration
https://owasp.org/www-pdf-archive/OWASP_IL_The_Universal_XSS_PDF_Vulnerability.pdf
https://onappsec.com/notes-on-ssrf-during-pdf-generation/
https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20presentations/DEFCON-27-Ben-Sadeghipour-Owning-the-clout-through-SSRF-and-PDF-generators.pdf
https://www.youtube.com/watch?v=kMirO25kulw
