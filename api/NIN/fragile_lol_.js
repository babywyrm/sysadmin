//
//
var http = require("http"),
    url = require("url"),
    path = require("path"),
    proxy_host = process.argv[2] || 'api.example.com',
    port = process.argv[3] || 8888,
    http_req = require('http');

http.createServer(function(request, response) {
  var clean_url = request.url.replace('/fragile','');
  console.log("------");
  
  var return_code = 200;
  var timeout = 0;
  var Y34RZ3R0R3M1X3D_flag = false;
  
  var Y34RZ3R0R3M1X3D = function(str) {
    if(Y34RZ3R0R3M1X3D_flag) {
      console.log('Y34RZ3R0R3M1X3D');
      var complexity = 0.01; // 0 to .99 if more then more letters in src string will be replaced by random ones 
      var randsArr = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>\'\":").split('').sort(function () { return 0.5 - Math.random()});
      var srcArr = (str).split('');
      for(var i = 0; i < str.length; i++) {
        if(srcArr[i] != ' ') { //ignore spaces
          srcArr[i] = (Math.random()>complexity) ? srcArr[i] : (randsArr.length) ? randsArr.shift() : srcArr[i] ; 
        }
      }
      return srcArr.join('');
    } else {
      return str;
    }
  }
  
  var downward_spiral = function() {
    timeout = 12000;
    console.log('downward_spiral'); //sleep 30 sec
  }
  
  var further_down_the_spiral = function() {
    timeout = 120000;
    console.log('further_down_the_spiral'); //sleep 5 min
  }
  
  var fixed = function() {
    console.log('fixed');
  }
  
  var query = require('url').parse(request.url,true).query;  
  var broken = function() {
    console.log(query.key)
    console.log('broken');
  }

  var things_fall_apart = function(){
    console.log('things_fall_apart');
    return_code = Math.floor((Math.random()*10)+400)
  }
  var sin_flag = false;
  var sin = function() {
    console.log('sin');
    sin_flag = true;
  }
  
  var heasitation_marks = function() {
    console.log('heasitation_marks');
  }
  
  if(Math.floor((Math.random()*10)+1) > 5) {
    console.log('something fragile about to happen!');
    switch(Math.floor((Math.random()*6)+1)) 
    {
     case 1:
       downward_spiral();
       break;
     case 2:
       further_down_the_spiral();
       break;
     case 3:
       fixed();
       break;
     case 4:
       things_fall_apart();
       break;
     case 5:
       sin();
       break;
     case 6:
       Y34RZ3R0R3M1X3D_flag = true;
    }
  }
  
  //build request 
  setTimeout((function() {
    var options = {
      host: proxy_host,
      path: clean_url,
      method: request.method,
      //headers: request.headers
    };
  
    callback = function(call_response) {
      var str = '';

      //another chunk of data has been recieved, so append it to `str`
      call_response.on('data', function (chunk) {
        if(!sin_flag) {
          str += chunk;
        }
      });

      call_response.on('end', function () {
        response.writeHead(return_code);
        response.end(Y34RZ3R0R3M1X3D(str));
      });
    }

    http_req.request(options, callback).end();

  }), timeout);
}).listen(parseInt(port, 10));

console.log("Fragile API server running at => http://localhost:" + port + "/\nCTRL + C to shutdown");

//
//
