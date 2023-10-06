(function _check_doc_domain(domain) {
  // This snippet tries to walk document.domain in case the parent frame changed it after our iframe was created and the script was loaded

  /*eslint no-unused-vars:0*/
  var test;

  if (!window) {
    return;
  }

  // If domain is not passed in, then this is a global call
  // domain is only passed in if we call ourselves, so we
  // skip the frame check at that point
  if (typeof domain === "undefined") {
    // If we're running in the main window, then we don't need this
    if (window.parent === window || !document.getElementById("__nb-script-iframe-async")) {
      return;// true;  // nothing to do
    }

    try {
      // If document.domain is changed during page load (from www.blah.com to blah.com, for example),
      // window.parent.window.location.href throws "Permission Denied" in IE.
      // Resetting the inner domain to match the outer makes location accessible once again
      if (window.document.domain !== window.parent.window.document.domain) {
        window.document.domain = window.parent.window.document.domain;
      }
    }
    catch (err) {
      // We could log this, but nothing else to do
    }
  }

  domain = document.domain;

  if (domain.indexOf(".") === -1) {
    // we've reached the top level domain
    return;// false;  // not okay, but we did our best
  }

  // 1. Test without setting document.domain
  try {
    test = window.parent.document;
    return;// test !== undefined;  // all okay
  }
  // 2. Test with document.domain
  catch (err) {
    document.domain = domain;
  }
  try {
    test = window.parent.document;
    return;// test !== undefined;  // all okay
  }
  // 3. Strip off leading part and try again
  catch (err) {
    domain = domain.replace(/^[\w\-]+\./, "");
  }

  _check_doc_domain(domain);
})();
