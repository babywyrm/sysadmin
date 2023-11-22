
https://github.com/erichelgeson/fragile


# ![fragile](https://github.com/erichelgeson/fragile/raw/master/img/60px-Fragile_cover_big.jpg) The Fragile API Proxy
A Nine Inch Nails themed API proxy for testing app resiliency.

## Rational:
When integrating apps to an API, they usually work, but when deploying those apps out to the public, they are behind web proxies, on unreliable/slow connections, and many other things you can't control.

The Fragile API Proxy is an easy way to add random errors into your API calls. 

Nine Inch Nails album names are surprisingly good function names for this usecase.

## Usage:
Goal: Deploy to an API gateway and any request pre-pended with /fragile/ will have subtle random errors introduced into the request or response. 

Fragile API call:
http://api.example.com/fragile/v1/dogs?key=:key&expand=owner

Will proxy to this API call, randomly introducing errors:
http://api.example.com/v1/dogs?key=:key&expand=owner


### Run locally:
`node serve.js [host to proxy to] [port to listen on]`

## Functions:

* ![Y34RZ3R0R3M1X3D](https://github.com/erichelgeson/fragile/raw/master/img/60px-Halo25_cover.jpg) Y34RZ3R0R3M1X3D - Randomly change a few characters in the response.
* ![downward_spiral](https://github.com/erichelgeson/fragile/raw/master/img/60px-TDSoriginal.jpg) downward_spiral - Add 12 seconds to the response
* ![fdts](https://github.com/erichelgeson/fragile/raw/master/img/60px-Fdts_cover.jpg) further_down_the_spiral - Add 2 minutes to the response
* ![fixed](https://github.com/erichelgeson/fragile/raw/master/img/60px-Fixed.jpg) fixed - randomly give no error :)
* ![broken](https://github.com/erichelgeson/fragile/raw/master/img/60px-Broken.jpg) broken - Mess with query string before sending
* ![tfa](https://github.com/erichelgeson/fragile/raw/master/img/60px-Tfa_cover.jpg) things_fall_apart - Random 400 error response
* ![sin](https://github.com/erichelgeson/fragile/raw/master/img/60px-Halo-4-US.jpg) sin - no body
* ![tdtwww](https://github.com/erichelgeson/fragile/raw/master/img/60px-TDTWWA_Cover.jpg) Todo: the_day_the_world_went_away - close connection without http response
* More to come. - http://www.ninwiki.com/Halo_numbers

## Caveats/Todos
* Literally hacked together while kids watched Tangled.
* JS is not my primary language, only second node.js thing I've built.
* Probability tweaks should be more easily configurable.
* More methods
