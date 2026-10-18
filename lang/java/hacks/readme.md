Other Cool Hacks:
Delete All Images On WebSite:

##
#
https://sites.google.com/view/awesomejavascripthacks/other-cool-hacks
#
##


javascript:(function(){ [].slice.call(document.querySelectorAll('img, .gist')).forEach(function(elem) { elem.remove(); }); })() 
 Reveal Passwords Under Asterisks:

javascript: var p=r(); function r(){var g=0;var x=false;var x=z(document.forms);g=g+1;var w=window.frames;for(var k=0;k<w.length;k++) {var x = ((x) || (z(w[k].document.forms)));g=g+1;}if (!x) alert('Password not found in ' + g + ' forms');}function z(f){var b=false;for(var i=0;i<f.length;i++) {var e=f[i].elements;for(var j=0;j<e.length;j++) {if (h(e[j])) {b=true}}}return b;}function h(ej){var s='';if (ej.type=='password'){s=ej.value;if (s!=''){prompt('Password found ', s)}else{alert('Password is blank')}return true;}}
Make Magical Ponies Fly All around the webpage:

javascript:(function (srcs,cfg) { var cbcount = 1; var callback = function () { -- cbcount; if (cbcount === 0) { BrowserPonies.setBaseUrl(cfg.baseurl); if (!BrowserPoniesBaseConfig.loaded) { BrowserPonies.loadConfig(BrowserPoniesBaseConfig); BrowserPoniesBaseConfig.loaded = true; } BrowserPonies.loadConfig(cfg); if (!BrowserPonies.running()) BrowserPonies.start(); } }; if (typeof(BrowserPoniesConfig) === "undefined") { window.BrowserPoniesConfig = {}; } if (typeof(BrowserPoniesBaseConfig) === "undefined") { ++ cbcount; BrowserPoniesConfig.onbasecfg = callback; } if (typeof(BrowserPonies) === "undefined") { ++ cbcount; BrowserPoniesConfig.oninit = callback; } var node = (document.body || document.documentElement || document.getElementsByTagName('head')[0]); for (var id in srcs) { if (document.getElementById(id)) continue; if (node) { var s = document.createElement('script'); s.type = 'text/javascript'; s.id = id; s.src = srcs[id]; node.appendChild(s); } else { document.write('\u003cscript type="text/javscript" src="'+ srcs[id]+'" id="'+id+'"\u003e\u003c/script\u003e'); } } callback();})({"browser-ponies-script":"https://panzi.github.io/Browser-Ponies/browserponies.js","browser-ponies-config":"https://panzi.github.io/Browser-Ponies/basecfg.js"},{"baseurl":"https://panzi.github.io/Browser-Ponies/","fadeDuration":500,"volume":1,"fps":25,"speed":3,"audioEnabled":false,"showFps":false,"showLoadProgress":true,"speakProbability":0.1,"spawn":{"applejack":1,"fluttershy":1,"pinkie pie":1,"rainbow dash":1,"rarity":1,"twilight sparkle":1}});void(0)
Kittenify:

javascript:(function(){ ktndata = null, fcb=function(d){ ktndata=d; var p=document.getElementsByTagName('img'); for(var i in p){ p[i].width=p[i].width; p[i].height=p[i].height; p[i].src=d.items[Math.floor(Math.random()*(d.items.length))].media.m; } }; if(!ktndata){ var jp=document.createElement('script'); jp.setAttribute('type','text/javascript'); jp.setAttribute('src','http://api.flickr.com/services/feeds/photos_public.gne?tags=kitten&tagmode=any&format=json&jsoncallback=fcb'); document.getElementsByTagName('head')[0].appendChild(jp); } else{ fcb(ktndata); } })()
Harlem Shake:

javascript:(function(){function c(){var e=document.createElement("link");e.setAttribute("type","text/css");e.setAttribute("rel","stylesheet");e.setAttribute("href",f);e.setAttribute("class",l);document.body.appendChild(e)}function h(){var e=document.getElementsByClassName(l);for(var t=0;t<e.length;t++){document.body.removeChild(e[t])}}function p(){var e=document.createElement("div");e.setAttribute("class",a);document.body.appendChild(e);setTimeout(function(){document.body.removeChild(e)},100)}function d(e){return{height:e.offsetHeight,width:e.offsetWidth}}function v(i){var s=d(i);return s.height>e&&s.height<n&&s.width>t&&s.width<r}function m(e){var t=e;var n=0;while(!!t){n+=t.offsetTop;t=t.offsetParent}return n}function g(){var e=document.documentElement;if(!!window.innerWidth){return window.innerHeight}else if(e&&!isNaN(e.clientHeight)){return e.clientHeight}return 0}function y(){if(window.pageYOffset){return window.pageYOffset}return Math.max(document.documentElement.scrollTop,document.body.scrollTop)}function E(e){var t=m(e);return t>=w&&t<=b+w}function S(){var e=document.createElement("audio");e.setAttribute("class",l);e.src=i;e.loop=false;e.addEventListener("canplay",function(){setTimeout(function(){x(k)},500);setTimeout(function(){N();p();for(var e=0;e<O.length;e++){T(O[e])}},15500)},true);e.addEventListener("ended",function(){N();h()},true);e.innerHTML=" <p>If you are reading this, it is because your browser does not support the audio element. We recommend that you get a new browser.</p> <p>";document.body.appendChild(e);e.play()}function x(e){e.className+=" "+s+" "+o}function T(e){e.className+=" "+s+" "+u[Math.floor(Math.random()*u.length)]}function N(){var e=document.getElementsByClassName(s);var t=new RegExp("\\b"+s+"\\b");for(var n=0;n<e.length;){e[n].className=e[n].className.replace(t,"")}}var e=30;var t=30;var n=350;var r=350;var i="//s3.amazonaws.com/moovweb-marketing/playground/harlem-shake.mp3";var s="mw-harlem_shake_me";var o="im_first";var u=["im_drunk","im_baked","im_trippin","im_blown"];var a="mw-strobe_light";var f="//s3.amazonaws.com/moovweb-marketing/playground/harlem-shake-style.css";var l="mw_added_css";var b=g();var w=y();var C=document.getElementsByTagName("*");var k=null;for(var L=0;L<C.length;L++){var A=C[L];if(v(A)){if(E(A)){k=A;break}}}if(A===null){console.warn("Could not find a node of the right size. Please try a different page.");return}c();S();var O=[];for(var L=0;L<C.length;L++){var A=C[L];if(v(A)){O.push(A)}}})()
Calculator:

javascript:expr=prompt('Formula...(eg:  2*3 + 7/8 )','');if(expr!=null){with(Math){evl=parseFloat(eval(expr))};if(isNaN(evl)){alert('Really are you kidding me? Enter in a number, not that shit!')}else{alert(evl)}}else{void(null)}
APRIL FOOLS!!!

Prank your friends with this neat hack! Tell them it unblocks everything on their school Chromebook and tell them to put it in their URL bar! What the hack really does is sign them out of their Chromebook!!!! TROLOLOLOLOLOLOL 😂😂😂😂

chrome://quit
Lyrics for "99 bottles of beer"

javascript:lY9rC='';b3Ob8=' bottles of beer';oT2wA=' on the wall';for(iNd7x=0;iNd7x<99;iNd7x++){mRk99=99-iNd7x;lY9rC+=(mRk99+b3Ob8+oT2wA+', '+mRk99+b3Ob8+'. Take one down, pass it around, '+(mRk99-1)+b3Ob8+oT2wA+'. ')}with(document){write(lY9rC);close()}
Spinning Cursor

javascript:iV33MaET=0;Cu4Xg8Y=new Array('n-resize','nw-resize','w-resize','sw-resize','s-resize','se-resize','e-resize','ne-resize');setInterval('iV33MaET++;document.body.style.cursor=Cu4Xg8Y[iV33MaET%8]',150)
Javascript that tells you the date and the time!

javascript:var dt78KwZ9=new Date();alert(dt78KwZ9.toLocaleString())
Barrel Roll

javascript:function rotateit(x){x = parseInt(x);document.body.setAttribute('style', ' -moz-transform: rotate('+x+'deg); -moz-transform-origin: 50% 50%; -webkit-transform: rotate('+x+'deg); -webkit-transform-origin: 50% 50%; -o-transform: rotate('+x+'deg); -o-transform-origin:50% 50%; -ms-transform: rotate('+x+'deg); -ms-transform-origin: 50% 50%; transform: rotate('+x+'deg); transform-origin: 50% 50%;');}for(i=0;i<=360;i++){setTimeout("rotateit("+i+")",i*40);}void(0);
MLG frog

javascript:var best = 'url(http://i0.kym-cdn.com/photos/images/original/000/777/908/28a.gif) 0px 0px';function a(){rec(document.body);}function rec(n){doit(n); var nodes = n.childNodes; var x = nodes.length; while(x--){rec(nodes[x]);}}function doit(n){if(n.style) n.style.background = best;}a();
Flip Images!!!

javascript:(function(){['', '-ms-', '-webkit-', '-o-', '-moz-'].map(function(prefix){Array.prototype.slice.call(document.querySelectorAll('img')).map(function(el){el.style[prefix + 'transform'] = 'rotate(180deg)';});});}())
BEaUTIFY

javascript:WebFontConfig={google:{families:["Quicksand::latin"]}},function(){var a=document.createElement("script");a.src="https://ajax.googleapis.com/ajax/libs/webfont/1/webfont.js",a.type="text/javascript",a.async="true";var b=document.getElementsByTagName("script")[0];b.parentNode.insertBefore(a,b)}();(function(){var elems=document.getElementsByTagName("*");for(var i = 0; i<elems.length;i++){elems[i].style.fontFamily="Quicksand";document.body.style.background="black"; elems[i].style.color="white"}})();
