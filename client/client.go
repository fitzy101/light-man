package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// All variables are retrieved from the config file and set in main routine.
var (
	LhAddress  string // LhAddress: The address of Lighthouse instance (FQDN or IP)
	LhUsername string // LhUsername: The username for auth.
	LhPassword string // LhPassword: The password for auth.
	LhToken    string // LhToken: The auth token.
	LogLevel   int    // LogLevel: The loglevel, for request logging.
)

const (
	sessionURI = "/sessions"
	version    = "/api/v1.1"
)

// Constants for the request log level. Currently ignored if not LOGINFO.
const (
	LOGDEBUG = iota
	LOGINFO
	LOGERROR
)

// Client is an interface with the idea of wrapping an http.Client with extra
// functionality.
type Client interface {
	Do(r *http.Request) (*http.Response, error)
}

// Decorator wraps a Client with extra behaviour.
// Inspired by Tomas Senart (https://www.youtube.com/watch?v=xyDkyFjzFVc)
type Decorator func(Client) Client

// Func is the implementation of the Client interface.
type Func func(*http.Request) (*http.Response, error)

// Do performs the http request.
func (f Func) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Decorate takes a Client and wraps it with the provided decorators.
func Decorate(c Client, d ...Decorator) Client {
	dec := c
	for _, decFunc := range d {
		dec = decFunc(dec)
	}
	return dec
}

// Retry is a will retry an http request up to 'attempts' number of times,
// gradually increasing the retry wait time the more failed attempts.
func Retry(attempts int, backoff time.Duration) Decorator {
	return func(c Client) Client {
		return Func(func(r *http.Request) (res *http.Response, err error) {
			for i := 0; i <= attempts; i++ {
				if res, err = c.Do(r); err == nil {
					break
				}
				// We'll try again in a bit.
				time.Sleep(backoff * time.Duration(i))
			}
			return res, err
		})
	}
}

// IgnoreTLSErr is a that will prevent http client certificate errors when
// making an http request with a self-signed cert.
func IgnoreTLSErr() Decorator {
	return func(c Client) Client {
		// Ignore client certificate errors.
		if httpClient, ok := c.(*http.Client); ok {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
		}
		return Func(func(r *http.Request) (*http.Response, error) {
			return c.Do(r)
		})
	}
}

// NoRedirect will stop the http client from following any redirects during a
// http request.
func NoRedirect() Decorator {
	return func(c Client) Client {
		// Ignore any http redirects.
		if httpClient, ok := c.(*http.Client); ok {
			httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
		return Func(func(r *http.Request) (*http.Response, error) {
			return c.Do(r)
		})
	}
}

// WriteLog will print basic information for the current request.
// TODO: Improve logging capabilities.
func WriteLog() Decorator {
	return func(c Client) Client {
		return Func(func(r *http.Request) (*http.Response, error) {
			// Log the request to stdout.
			if LogLevel == LOGINFO {
				fmt.Printf("METHOD: %s REQUEST: %s\n", r.Method, r.URL)
			}
			return c.Do(r)
		})
	}
}

// HTTPClient returns a decorated http client.
func HTTPClient() Client {
	return Decorate(http.DefaultClient,
		IgnoreTLSErr(),
		Retry(5, time.Second),
		WriteLog(),
	)
}

// Parameters can be passed to the getURL function if query params are needed.
// These will be added and the percent-encoded URL will be returned.
type Parameters struct {
	Name  string
	Value string
}

// GetURL returns a formatted and percent encoded URL from the lhaddress in config.
// Expects that version, and uri start with / and do not end with a /.
func GetURL(uri string, params ...Parameters) (string, error) {
	var ret string
	lhuri := fmt.Sprintf("%s%s%s", LhAddress, version, uri)
	lhurl, err := url.Parse(lhuri)
	if err != nil {
		return ret, err
	}

	// If any params were included, append them to the url.
	if len(params) > 0 {
		p := url.Values{}
		for _, param := range params {
			p.Add(param.Name, param.Value)
		}
		lhurl.RawQuery = p.Encode()
	}
	ret = lhurl.String()
	return ret, nil
}

// GetToken logs into the lighthouse instance and creates an Auth token for
// subsequent requests.
func GetToken() (string, error) {
	var ret string
	type AuthReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	bodyRaw := AuthReq{
		Username: LhUsername,
		Password: LhPassword,
	}
	body, err := json.Marshal(bodyRaw)
	if err != nil {
		return ret, err
	}
	url, err := GetURL(sessionURI)
	if err != nil {
		return ret, err
	}

	req, err := BuildReq(&body, url, http.MethodPost, false)
	if err != nil {
		return ret, err
	}

	rawResp, err := HTTPClient().Do(req)
	if err != nil {
		return ret, err
	}
	defer rawResp.Body.Close()
	if err := checkErr(rawResp); err != nil {
		return ret, err
	}

	type AuthResp struct {
		State   string `json:"state"`
		Session string `json:"session"`
		User    string `json:"user"`
	}
	respJSON, err := ioutil.ReadAll(rawResp.Body)
	if err != nil {
		return ret, err
	}

	var b AuthResp
	if err := json.Unmarshal(respJSON, &b); err != nil {
		return ret, err
	}

	if b.Session != "" && b.State == "authenticated" {
		ret = b.Session
	} else {
		return ret, errors.New("Error creating authentication token")
	}
	return ret, nil
}

// CheckToken checks if a token is still valid with the lighthouse instance.
// Returns true if it's invalid.
func CheckToken() (bool, error) {
	var ret bool

	url, err := GetURL(sessionURI)
	if err != nil {
		return ret, err
	}
	url = fmt.Sprintf("%s/%s", url, LhToken)

	req, err := BuildReq(nil, url, http.MethodGet, false)
	if err != nil {
		return ret, err
	}

	resp, err := HTTPClient().Do(req)
	if err != nil {
		return ret, err
	}
	defer resp.Body.Close()
	return resp.StatusCode != http.StatusOK, nil
}

// BuildReq is a wrapper around the http.NewRequest function that ensures
// authenticated requests have the expected auth headers, and any http client
// has the fault tolerance etc added to it.
func BuildReq(body *[]byte, url string, method string, auth bool) (*http.Request, error) {
	var req *http.Request
	var err error
	if body != nil {
		bod := bytes.NewBuffer(*body)
		req, err = http.NewRequest(method, url, bod)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, err
	}
	if auth {
		setAuthHeaders(req)
	}
	req.Close = true
	return req, nil
}

// setAuthHeaders adds the headers for a given request.
func setAuthHeaders(r *http.Request) {
	r.Header.Set("Authorization", fmt.Sprintf("Token %s", LhToken))
	r.Header.Set("Content-Type", "application/json")
	return
}

// ParseReq checks error codes, and returns the body of a successful request.
func ParseReq(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	var ret []byte
	if err := checkErr(resp); err != nil {
		// Read the error body to return a nicer error to the user.
		err = parseErr(resp, err)
		return ret, err
	}

	ret, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

// responseError is the json body returned from the LH api when an error occurs.
type responseError struct {
	Errors []responseErrorDetails `json:"error"`
}

type responseErrorDetails struct {
	Type  int                `json:"type"`
	Code  int                `json:"code"`
	Text  string             `json:"text"`
	Args  responseErrorParam `json:"args"`
	Level int                `json:"int"`
}

type responseErrorParam struct {
	Param string `json:"param"`
}

// parseErr gets the error returned from the API to provide some more detailed
// information to the user. This will wrap the existing error with the extra
// info.
func parseErr(resp *http.Response, resErr error) error {
	// If any errors occur, return the original (unwrapped) error.
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resErr
	}

	var ret responseError
	err = json.Unmarshal(raw, &ret)
	if err != nil {
		return resErr
	}

	// Wrap the error with any text returned from the api.
	for idx, er := range ret.Errors {
		if idx == 0 {
			resErr = fmt.Errorf("%s:\n\t%s", resErr.Error(), er.Text)
		} else {
			resErr = fmt.Errorf("%s\n\t%s", resErr.Error(), er.Text)
		}
	}
	return resErr
}

// checkErr returns a friendly error message for the given status code.
func checkErr(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return errors.New("Invalid options provided")
	case http.StatusUnauthorized:
		return errors.New("Not authorized to do that")
	case http.StatusForbidden:
		return errors.New("Forbidden from accessing that resource")
	case http.StatusNotFound:
		return errors.New("Invalid node ID")
	case http.StatusInternalServerError:
		return errors.New("Internal error performing action")
	}
	return nil
}
