Ribbit.getAuthenticatedUserIniFrame = function(callback, name, windowOptions) {
	var win = null;
	var gotUrlCallback = function(result) {
		console.log(result);
		if (result.hasError) {
			callback(new Ribbit.RibbitException("Cannot get request token, check application credentials.", 0)); //the request for an oAuth uri has gone wrong
		} else {
			var timeOutPoint = new Date().getTime() + 300000;
			var pollApproved = function() { 
						var callback = function(val) {
							//setInterval
							if (!val.hasError) {
								callback(true);
								console.log('We\'re in!');
								win.remove(); //remove the iFmame
								$('.body').show(); //show the body of the DOM
								return;
							} else if (new Date().getTime() > timeOutPoint) { // leave timeout in removing iFrame and giving control back
								callback(new Ribbit.RibbitException("Timed out.", 0)); //timed out
							} else {
								pollApproved();
							}
						};
						Ribbit.checkAuthenticatedUser(callback); //returns true if we have an authenticated user (Ribbit.userID != null) for the browser
			};
			win = $('<iframe src ="'+result+'" width="100%" height="100%"><p>Your browser does not support iframes.</p></iframe>'); //create an iFrame to overlay atop the current page
			$('.body').hide(); //hide the body
			pollApproved(); //poll the iFrame by merely checking the Ribbit userid
		}
	};
	Ribbit.createUserAuthenticationUrl(gotUrlCallback); //request to Ribbit paltform for one time oAuth URI
};
