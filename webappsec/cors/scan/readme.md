
##
#
https://github.com/Miguer-dev/cors_watcher
#
https://github.com/omranisecurity/CorsOne
#
##


A Go tool to check CORS policies on websites, with configurable options for HTTP requests. Pasted image 20240821001633.png

# CORS_Watcher
A Go tool to check CORS policies on websites, with configurable options for HTTP requests.
![Pasted image 20240821001633.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821001633.png)
## Features
- Capable of detecting a wide range of CORS vulnerabilities.
- Multi-threading tool.
- Allows setting custom origin headers.
- Supports scanning multiple URLs in a single command.
- User-friendly interface with color-coded tags based on risk level.
- And more, highly configurable.
## Installation
Download [release](https://github.com/Miguer-dev/cors_watcher/releases/) binary
## Usage
### Options
```bash
./cors-watcher [flags]
```
- `-url`: URL to check its CORS policy. It must start with `http://` or`https://`.
- `-method`: Set the request method (GET, POST, PUT, DELETE, PATCH).
- `-headers`: Set request headers in the format `key:value, key:value, ...`.
- `-data`: Data to send in the request (for methods like POST).
- `-origins-file`: Specify the filename containing the list of origins.
- `-only-origins`: Use only the origins from the specified origins list file.
- `-requests-file`: Specify the filename containing the list of requests, using JSON format for each entry:
`{"url": "https://url1.com", "method": "POST", "headers": {"header1": "value1", "header2": "value2"}, "data": "data1"}`
- `-timeout`: Set the request timeout (in seconds).
- `-delay`: Set the delay between requests (in seconds).
- `-proxy`: Set the proxy (HTTP or SOCKS5).
- `-output`: Specify the filename to save the results in a readable format.
- `-output-json`: Specify the filename to save the results in json format.
- `-output-csv`: Specify the filename to save the results in csv format.
- `-output-yaml`: Specify the filename to save the results in yaml format.
- `-version`: Show the tool's version.
### Tagging System
Tags highlight relevant information found regarding the website's CORS policies. The color of the tag indicates the risk level (green = low, yellow = medium, red = high).
- ![Pasted image 20240821002147.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821002147.png) - Headers containing `Access-Control-*` were found.
- ![Pasted image 20240821003419.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821003419.png) - The `Access-Control-Allow-Origin` header was found. The color may vary depending on its value and the risk it represents:
	- ![Pasted image 20240821002446.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821002446.png)  - **Low risk** as it matches the website's origin.
	- ![Pasted image 20240821003735.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821003735.png) - **Low risk** as it automatically disables `Access-Control-Allow-Credentials`.
	- ![Pasted image 20240821003931.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821003931.png) - **Medium risk** although the value is a possible domain of the attacker, it depends on the `Access-Control-Allow-Credentials` value for higher risk.
- ![Pasted image 20240821004406.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821004406.png) - The `Access-Control-Allow-Credentials` header was found. The color may vary depending on its value and the associated risk:
	- ![Pasted image 20240821004532.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821004532.png) - **Low risk** as it’s set to `false`, not allowing credential transmission.
	- ![Pasted image 20240821004737.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821004737.png) - **High risk** if set to `true` and `Access-Control-Allow-Origin` is misconfigured.
	- ![Pasted image 20240821004938.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821004938.png) - **Low risk** as although it's set to `true`, `Access-Control-Allow-Origin` is not vulnerable.
- ![Pasted image 20240821005218.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821005218.png) - The `http` protocol is used in `Access-Control-Allow-Origin`, which could be exploited by a Man-in-the-Middle attack.
- ![Pasted image 20240821005342.png](https://github.com/Miguer-dev/cors_watcher/blob/main/images/Pasted%20image%2020240821005342.png) - The `Vary: Origin` header is missing, which could lead to client-side cache poisoning.
### Examples
1. **Check CORS for a single URL:**
```bash
./cors-watcher -url https://example.com
```
2. **Make a POST request with data and headers:**
```bash
./cors-watcher -url "https://example.com" -method POST -headers "Content-Type:application/json" -data '{"key": "value"}'
```
 3. **Use an origin list file to check multiples CORS:**
```bash
./cors-watcher -url https://example.com -origins-file origins
```
4. **Make requests from a file:**
```bash
./cors-watcher -requests-file requests
```
5. **Set delay between requests for pass time rate filters on target websites**
```bash
./cors-watcher -requests-file requests -delay 0.5
```
## Misconfigurations and vulnerabilities
- **Reflected Origin**: Checks if the server reflects the origin value from the request back in the `Access-Control-Allow-Origin` header, potentially allowing attackers to control the allowed origin.
- **Modified Origin (Prefix/Suffix Manipulation)**: Detects if the server accepts altered origins that include additional prefixes or suffixes.
- **Null Origin**: Verifies if the server accepts requests with a `null` origin, which can bypass origin restrictions.
- **Insecure `http://` in `Access-Control-Allow-Origin`**: Checks if `http://` origins are allowed, which can enable man-in-the-middle attacks.
- **Trusted Subdomains Exploitation**: Evaluates if trusted subdomains are allowed, which could be exploited if a subdomain has XSS vulnerabilities.
- **Subdomains with Special Characters**: Determines if subdomains with special characters are accepted, which some browsers may mishandle.
- **Client Cache Poisoning (Missing `Vary: Origin` Header)**: Checks if the `Vary: Origin` header is missing, potentially leading to cache poisoning.

For more details on these vulnerabilities -> [exploiting-cors-misconfigurations-for-bitcoins-and-bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
## License
This project is licensed under the [MIT License](https://github.com/Miguer-dev/cors_watcher/blob/main/LICENSE).
