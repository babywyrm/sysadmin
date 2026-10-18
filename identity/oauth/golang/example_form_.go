package form

import (
	"io"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/jwt"
)

func encode(values url.Values) (contentLen int, body io.Reader) {
	data := values.Encode()
	return len(data), strings.NewReader(data)
}

// ClientCredentials returns a client_credentials type of form data map
func ClientCredentialsAccessToken(clientId, clientSecret string) (contentLen int, body io.Reader) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
	}
	return encode(data)
}

func PasswordAccessToken(username, password, clientId, clientSecret string) (contentLen int, body io.Reader) {
	formData := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"client_id":  {clientId},
	}

	if clientSecret != "" {
		formData.Set("client_secret", clientSecret)
	}
	return encode(formData)
}

func Introspection(token, clientId, clientSecret string) (contentLen int, body io.Reader) {
	data := url.Values{
		"token":         {token},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
	}
	return encode(data)
}

func Refresh(refreshToken, clientId, clientSecret string) (contentLen int, body io.Reader) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
	}
	return encode(data)
}

func TokenExchange(token, clientId, clientSecret string) (contentLen int, body io.Reader, err error) {
	t, err := jwt.ParseString(token)
	if err != nil {
		return 0, nil, err
	}

	data := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_issuer":     {t.Issuer()},
		"subject_token":      {token},
		"client_id":          {clientId},
		"client_secret":      {clientSecret},
	}

	contentLen, body = encode(data)
	return contentLen, body, nil
}
