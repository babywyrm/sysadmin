// with some inspiration from https://jsfiddle.net/uggmnho5/4/
const base = url.substr(0,url.lastIndexOf("/")) + "/";

$.get(url).then((htmlText) => {
    htmlText = htmlText.replace(/src=("|\')(?!https?:|\/)/g, 'src=$1' + base) // expand to to other  needs

    const myDocURL = URL.createObjectURL(new Blob([htmlText], {
        type: 'text/html'
    }));


    takeSnapshotOfURL(myDocURL,div.dataset)
        .then((canvas) => {
            div.parentNode.replaceChild(canvas,div);

        });
})

function takeSnapshotOfURL(url,options) {
    const iframe = document.createElement('iframe');
    iframe.src = url;
    iframe.style.cssText = 'position: absolute; opacity:0; z-index: -9999';
    document.body.appendChild(iframe);
    return new Promise(function (res, rej) {
        iframe.onload = function (e) {
            const html2canvasOptions = {
                logging: true,
                background:"white",
            };
            html2canvas(iframe.contentDocument.documentElement, html2canvasOptions)
                .then(function (canvas) {
                    document.body.removeChild(iframe);
                    res(canvas);
                })
                .catch(rej);
        };
        iframe.onerror = rej;
    });
}
