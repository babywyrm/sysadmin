/*
  Yara signatures for identifying secrets in text files. Requires libmagic!
  Mostly all stolen from Trufflehog regexes:
  - https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json
*/

import "magic"

rule RSA_PRIVATE_KEY {
  meta:
  	description = "RSA key patterns"
  strings:
  	$rsa = /-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}/
  condition:
  	$rsa and magic.type() contains "text"
}

rule SSH_EC_PRIVATE_KEY {
  meta:
  	description = "SSH (EC) private key patterns"
  strings:
  	$pattern = /-{5}BEGIN\sEC\sPRIVATE\sKEY-{5}/
  condition:
  	$pattern and magic.type() contains "text"
}

rule PGP_PRIVATE_KEY {
  meta:
  	description = "PGP Private key patterns"
  strings:
  	$pattern = /-{5}BEGIN\sPGP\sPRIVATE\sKEY-{5}/
  condition:
  	$pattern and magic.type() contains "text"
}

rule AWS_KEY {
  meta:
  	description = "AWS key patterns"
  strings:
  	$aws_access_key_id = /AKIA[0-9A-Z]{16}/
    $aws_mws_auth_token = /amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/
  condition:
  	any of them and magic.type() contains "text"
}

rule facebook_keys {
  meta:
  	description = "facebook key patterns"
  strings:
  	$access_token = /EAACEdEose0cBA[0-9A-Za-z]+/
    $facebook_oauth = /[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]/
  condition:
  	any of them and magic.type() contains "text"
}

rule github_key {
  meta:
  	description = "github key patterns"
  strings:
  	$access_token = /[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]/
  condition:
  	$access_token and magic.type() contains "text"
}

rule generic_api_key {
  meta:
  	description = "generic key patterns"
  strings:
  	$generic_key = /[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]/
    $generic_secret = /[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]/
  condition:
  	any of them and magic.type() contains "text"
}

rule google_keys {
  meta:
  	description = "Google key patterns"
  strings:
  	$google_api = /AIza[0-9A-Za-z\\-_]{35}/
    $google_oauth = /[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com/
    $gmail_oauth_access_key = /ya29\\.[0-9A-Za-z\\-_]+/
    $GCP_service_account = /\"type\": \"service_account\"/
  condition:
  	any of them and magic.type() contains "text"
}

rule heroku_api_key {
  meta:
  	description = "heroku key patterns"
  strings:
  	$heroku_key = /[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/
  condition:
  	$heroku_key and magic.type() contains "text"
}

rule mailchimp_api_key {
  meta:
  	description = "mailchimp key patterns"
  strings:
  	$mailchimp_key = /[0-9a-f]{32}-us[0-9]{1,2}/
  condition:
  	$mailchimp_key and magic.type() contains "text"
}

rule mailgun_api_key {
  meta:
  	description = "mailgun key patterns"
  strings:
  	$mailgun_key = /key-[0-9a-zA-Z]{32}/
  condition:
  	$mailgun_key and magic.type() contains "text"
}

rule password_url {
  meta:
  	description = "URL string containing a password"
  strings:
  	$password_url = /[a-z-0-9]{,8}:\/{2}[a-z-0-9]{,16}\:[a-z-0-9-!@#$%^&*()_+\,.<>?]{,16}@[a-z]{,64}\.[a-z]{,8}/ nocase
  condition:
  	$password_url and magic.type() contains "text"
}

rule paypal_braintree {
  meta:
  	description = "paypal braintree access token"
  strings:
  	$access_token = /access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}/
  condition:
  	$access_token and magic.type() contains "text"
}

rule picatic_api_key {
  meta:
  	description = "Picatic API Key"
  strings:
  	$api_key = /sk_live_[0-9a-z]{32}/
  condition:
  	$api_key and magic.type() contains "text"
}

rule stripe_api_keys {
  meta:
  	description = "Stripe API"
  strings:
  	$api_key = /sk_live_[0-9a-zA-Z]{24}/
    $restricted_api_key = /rk_live_[0-9a-zA-Z]{24}/
  condition:
  	any of them and magic.type() contains "text"
}

rule square_keys {
  meta:
  	description = "Square secrets"
  strings:
  	$square_access_token = /sq0atp-[0-9A-Za-z\\-_]{22}/
    $square_oauth_secret = /sq0csp-[0-9A-Za-z\\-_]{43}/
  condition:
  	any of them and magic.type() contains "text"
}

rule twilio_api_key {
  meta:
  	description = "Twilio API key"
  strings:
  	$api_key = /SK[0-9a-fA-F]{32}/
  condition:
  	$api_key and magic.type() contains "text"
}

rule twitter_keys {
  meta:
  	description = "Twitter API key"
  strings:
  	$access_key = /[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}/
    $oauth = /[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]/
  condition:
  	any of them and magic.type() contains "text"
}

/* commenting slack stuff out as needs to be tested
rule slack {
  meta:
  	description = "Slack API key patterns"
  strings:
  	$slack_token = /(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})/
  condition:
  	$slack_token and magic.type() contains "text"
}
rule slack_webhook {
  meta:
  	description = "Slack Webhook"
  strings:
  	$slack_webhook_url = /https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}/
  condition:
  	$slack_webhook_url and magic.type() contains "text"
}
*/
