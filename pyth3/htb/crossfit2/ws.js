$("#sendmsg").on("keypress", function(event) {
  if (13 === event.which) {
    $(this).attr("disabled", "disabled");
    var s = $("#sendmsg").val();
    if ("" !== s) {
      $("#chat-messages").append('<li class="send-msg float-right mb-2"><p class="msg_display pt-1 pb-1 pl-2 pr-2 m-0 rounded">' + s + "</p></li>");
      /** @type {!Object} */
      var t = new Object;
      t.message = s;
      t.token = token;
      ws.send(JSON.stringify(t));
      $("#sendmsg").val("");
      $(this).removeAttr("disabled");
      updateScroll();
    }
  }
}
