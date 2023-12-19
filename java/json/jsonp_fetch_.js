
//
// jsonp-usage.js
//

// Example usage: Fetch it's own code from GitHub

JSONP( 'https://api.github.com/gists/1900694?callback=?', function( response ) {
	console.log( 'JSONP function:', response.data.files['jsonp.js'].content );
});




//
// jsonp.js
//

function JSONP( url, callback ) {
	var id = ( 'jsonp' + Math.random() * new Date() ).replace('.', '');
	var script = document.createElement('script');
	script.src = url.replace( 'callback=?', 'callback=' + id );
	document.body.appendChild( script );
	window[ id ] = function( data ) {
		if (callback) {
			callback( data );
		}
	};
}

