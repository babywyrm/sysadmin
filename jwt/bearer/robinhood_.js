// a reference for getting the robinhood API bearer token
// returns a jquery promise. really is this broken...
// in CONSOLE need jquery too..
var __ss = document.createElement("script");__ss.onload=load_example;__ss.src="https://code.jquery.com/jquery-3.3.1.min.js";document.body.appendChild(__ss);
/**

  Reference

  If you want to hack on RobinHood in the browser, you'll need auth.
  
*/
function get_robinhood_bearer_token() {
  console.log("get_robinhood_bearer_token()");
  let prom = $.Deferred();
  let _idb = window.indexedDB.open("localforage", 2);
  _idb.onsuccess = function(e) {
    let db = _idb.result;
    let trans = db.transaction("keyvaluepairs").objectStore("keyvaluepairs");
    let query = trans.get("reduxPersist:auth");
    query.onsuccess = function(e) {
      // yes, really have to decode it twice.. can't be correct.
      let _data = JSON.parse(query.result)
      let is_string = typeof _data === "string";
      if(is_string) {
        _data = JSON.parse(_data);
      }
      prom.resolve(_data[1][1], _data);
    }
  }
  return prom.promise();
}

// example!
function load_example() {
  var promised = get_robinhood_bearer_token();
  promised.then(function(token, db_json) {
    console.log("GOT THE TOKEN", token);
  });  
}
