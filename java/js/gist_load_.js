/**
 *  Shamelessly stolen from http://blog.jeansebtr.com/post/36590722386/async-loading-of-githubs-gists-without-jquery-31-loc
 *
 *  Use like this: <gist data-username="brandonb927" data-id="4138162" data-file="gists2.js"><a href="https://gist.github.com/brandonb927/4138162#file_gists2.js">Gist</a></gist>
 * UPDATED 02/06/2013: Github implemented Namespaced Gists a few hours ago, which means gist.github.com/4149074 now redirects to gist.github.com/brandonb927/4149074 and I have updated the gist to reflect this new format
 *
 */

(function(){
    var gists = document.getElementsByTagName('gist');
    function embed(username, id, file, i, tag) {
        window['embed_gist_'+i] = function(gist) {
            var tmp = document.createElement('div');
            tmp.innerHTML = gist.div;
            tag.parentNode.replaceChild(tmp.firstChild, tag);
        };
        var url = 'https://gist.github.com/'+username+'/'+id+'.json?callback=embed_gist_'+i;
        if(file) {
            url += '&file='+file;
        }
        var script = document.createElement('script');
        script.type = 'text/javascript';
        script.src = url;
        document.head.appendChild(script);
    }
    if(gists.length) {
        var css = document.createElement('link');
        css.rel = 'stylesheet';
        css.href= 'https://gist.github.com/assets/embed-8f95cc15c5dcf1117ab18c08ff316641.css';
        document.head.appendChild(css);
    }
    for(var i=0; i<gists.length; i++) {
        var username = gists[i].getAttribute('data-username');
        var id = gists[i].getAttribute('data-id');
        var file = gists[i].getAttribute('data-file');
        if(id) {
            embed(username, id, file, i, gists[i]);
        }
    }
})();
