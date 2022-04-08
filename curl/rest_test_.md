http://blogs.plexibus.com/2009/01/15/rest-esting-with-curl/
http://stackoverflow.com/questions/298745/how-do-i-send-a-cross-domain-post-request-via-javascript

POSTS CURL
curl -i -H "Accept: application/json" -X GET http://localhost:3000/posts.json
curl -i -H "Accept: application/json" -X GET http://localhost:3000/posts/2.json
curl -i -H "Accept: application/json" -X POST -d "post[title]=meu titulo&post[content]=meu conteudo" http://localhost:3000/posts.json
curl -i -H "Accept: application/json" -X PUT -d "post[title]=meu titulo2" http://localhost:3000/posts/1.json
curl -i -H "Accept: application/json" -X DELETE http://localhost:3000/posts/1.json

COMMENTS CURL
curl -i -H "Accept: application/json" -X GET http://localhost:3000/posts/2/comments.json
curl -i -H "Accept: application/json" -X GET http://localhost:3000/posts/2/comments/2.json
curl -i -H "Accept: application/json" -X POST -d "comment[email]=a@a.aa&comment[content]=aaa" http://localhost:3000/posts/2/comments.json
curl -i -H "Accept: application/json" -X PUT -d "comment[email]=b@a.aa&comment[content]=bbb" http://localhost:3000/posts/2/comments/2.json
curl -i -H "Accept: application/json" -X DELETE http://localhost:3000/posts/2/comments/2.json


POSTS AJAX
$.ajax({ 
  type: 'GET', 
  url: 'http://localhost:3000/posts.json', 
  crossDomain: true, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'GET', 
  url: 'http://localhost:3000/posts/2.json', 
  crossDomain: true, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'POST', 
  url: 'http://localhost:3000/posts.json', 
  crossDomain: true, 
  data: { 
    post: {
      title: 'ajax using jquery',
      content: 'jquery rocks'
    }
  }, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'PUT', 
  url: 'http://localhost:3000/posts/3.json', 
  crossDomain: true, 
  data: { 
    post: {
      title: 'atualizado!',
      content: 'content atualizado'
    }
  }, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'DELETE', 
  url: 'http://localhost:3000/posts/3.json', 
  crossDomain: true, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});

COMMENTS AJAX
$.ajax({ 
  type: 'GET', 
  url: 'http://localhost:3000/posts/2/comments.json', 
  crossDomain: true, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'GET', 
  url: 'http://localhost:3000/posts/2/comments/1.json', 
  crossDomain: true, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'POST', 
  url: 'http://localhost:3000/posts/2/comments.json', 
  crossDomain: true, 
  data: { 
    comment: {
      email: 'ajax & jquery',
      content: 'comment via ajax'
    }
  }, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'PUT', 
  url: 'http://localhost:3000/posts/2/comments/5.json', 
  crossDomain: true, 
  data: { 
    comment: {
      email: 'atualizado@aa.aa',
      content: 'content atualizado'
    }
  }, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
$.ajax({ 
  type: 'DELETE', 
  url: 'http://localhost:3000/posts/2/comments/5.json', 
  crossDomain: true, 
  dataType: 'json', 
  success: function() { 
    console.log(arguments); 
  }, 
  error: function() { 
    console.log(arguments); 
  } 
});
