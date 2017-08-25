// light-man is a tool for communicating with an Opengear Lighthouse instance
// via cli, utilising the REST API. Currently implemented are:
// add, delete, list, and shell.
//
// Written with go 1.8, however would probably run on earlier versions.
// To compile, navigate to the source folder and type 'make'. You'll need to
// install the dependencies with `go get ./...`.
//
// TODO:
// - Implement filtering for the list command.
// - Implement an 'approve' command.
// - Refactor into seperate files for easier maintenance/reading.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	// Lighthouse vars.
	lhaddress  string
	lhusername string
	lhpassword string

	// Console Server vars.
	address  string
	username string
	password string
	name     string
	bundle   string
	noauto   bool
	id       string

	// Housekeeping vars.
	command   string
	authToken string
)

const (
	dcommand  = "the command to run with light-man"
	daddress  = "URL of the Lighthouse instance"
	dnaddress = "FQDN or IP Address of the node"
	dusername = "user name for a Lighthouse user (default is 'root')"
	dpassword = "password for the Lighthouse user (default is 'default')"
	dname     = "name of the node to add"
	dbundle   = "name of the enrollment bundle"
	dauto     = "indicates the node should NOT be auto-approved on enrollment"
	did       = "the identifier for a node - find with the list command"

	version    = "/api/v1"
	yamlSpace  = "  "
	configfile = ".oglh"
	sessionURI = "/sessions"
	nodeURI    = "/nodes"

	sshPort = 22
	sshConn = "tcp"
)

func init() {
	flag.StringVar(&command, "c", "", dcommand)
	flag.StringVar(&address, "a", "", daddress)
	flag.StringVar(&username, "u", "root", dusername)
	flag.StringVar(&password, "p", "default", dpassword)
	flag.StringVar(&name, "n", "", dname)
	flag.StringVar(&bundle, "b", "", dbundle)
	flag.StringVar(&id, "i", "", did)
	flag.BoolVar(&noauto, "no", false, dauto)
}

func usage() string {
	var sbuff bytes.Buffer
	sbuff.WriteString("Usage: light-man -c [COMMAND] [OPTIONS]...\n")

	// configure command
	sbuff.WriteString("\tconfigure: set up light-man with your Lighthouse credentials\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-a: %s\n", daddress))
	sbuff.WriteString(fmt.Sprintf("\t\t-u: %s\n", dusername))
	sbuff.WriteString(fmt.Sprintf("\t\t-p: %s\n", dpassword))

	sbuff.WriteString("\tadd: add a new node to the Lighthouse\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-a: %s\n", dnaddress))
	sbuff.WriteString(fmt.Sprintf("\t\t-u: %s\n", dusername))
	sbuff.WriteString(fmt.Sprintf("\t\t-p: %s\n", dpassword))
	sbuff.WriteString(fmt.Sprintf("\t\t-n: %s\n", dname))
	//sbuff.WriteString(fmt.Sprintf("\t\t-b: %s\n", dbundle)) // Not implemented
	sbuff.WriteString(fmt.Sprintf("\t\t-no: %s\n", dauto))
	sbuff.WriteString("\tlist: list all nodes on the Lighthouse\n")
	// TODO implement filtering by node status.
	// sbuff.WriteString(fmt.Sprintf("\t\t-s: %s\n", dlist))

	sbuff.WriteString("\tdelete: delete a node from the Lighthouse\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-i: %s\n", did))

	sbuff.WriteString("\tshell: get a port manager shell on the Lighthouse\n")

	return sbuff.String()
}

func main() {
	flag.Usage = func() {
		exitErr(usage())
	}
	flag.Parse()
	if len(os.Args) == 1 {
		exitErr(usage())
	}

	// Check the required fields were provided.
	if err := validate(); err != nil {
		exitErr(err.Error())
	}

	// Catch any segfaults within runCommand().
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("Error running command.. check the Lighthouse is accessible or reconfigure light-man.")
			exitErr(msg)
		}
	}()

	msg, err := runCommand(command)
	if err != nil {
		exitErr(err.Error())
	}
	exitSuccess(msg)
}
func runCommand(command string) (string, error) {
	var msg string
	switch command {
	case "configure":
		lhaddress = address
		msg, err := configure(address, username, password)
		if err != nil {
			return msg, err
		}
		return msg, nil
	case "add":
		if err := loadConfiguration(); err != nil {
			return msg, err
		}
		msg, err := addNode(address, username, password, name, bundle, noauto)
		if err != nil {
			return msg, err
		}
		return msg, nil
	case "list":
		if err := loadConfiguration(); err != nil {
			return msg, err
		}
		msg, err := listNodes()
		if err != nil {
			return msg, err
		}
		return msg, nil
	case "delete":
		if err := loadConfiguration(); err != nil {
			return msg, err
		}
		msg, err := deleteNode()
		if err != nil {
			return msg, err
		}
		return msg, nil
	case "shell":
		if err := loadConfiguration(); err != nil {
			return msg, err
		}
		msg, err := getShell()
		if err != nil {
			return msg, err
		}
		return msg, nil
	default:
		return msg, fmt.Errorf("%s is not a valid command", command)
	}
}

func validate() error {
	if command == "" {
		return errors.New("command (-c) must be provided")
	}

	// No args for list.
	if command == "list" {
		return nil
	}

	// ID required for delete.
	if command == "delete" {
		if id == "" {
			return errors.New("id (-i) must be provided")
		}
	}

	// Address required for configure and add.
	if command == "add" || command == "configure" {
		if address == "" {
			return errors.New("address (-a) must be provided")
		}

		// Trim any trailing slash if we're configuring light-man,
		// and force https.
		if command == "configure" {
			match, _ := regexp.MatchString(`^https://`, address)
			if !match {
				return errors.New("address must start with https://")
			}
			aL := len(address)
			if address[aL-1:] == "/" {
				address = address[:aL-1]
			}
		}
		if command == "add" {
			if name == "" {
				return errors.New("name (-n) must be provided")
			}
		}
	}
	return nil
}

// getConfigdir returns the filepath to the light-man configuration file.
func getConfigdir() (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", err
	}
	config := fmt.Sprintf("%s/%s", user.HomeDir, configfile)
	return config, nil
}

// configure sets up the light-man configuration file.
func configure(address, username, password string) (string, error) {
	var ret string
	configdir, err := getConfigdir()
	if err != nil {
		return ret, err
	}

	file, err := os.Create(configdir)
	defer file.Close()
	if err != nil {
		return ret, err
	}

	var fbuff bytes.Buffer

	// We're using YAML for the configuration here.
	fbuff.WriteString(fmt.Sprintf("lighthouse_configuration:\n"))
	fbuff.WriteString(fmt.Sprintf("%slighthouse: %s\n", yamlSpace, address))
	fbuff.WriteString(fmt.Sprintf("%suser: %s\n", yamlSpace, username))
	fbuff.WriteString(fmt.Sprintf("%spassword: %s\n", yamlSpace, password))
	_, wErr := file.WriteString(fbuff.String())
	if wErr != nil {
		return ret, wErr
	}
	ret = fmt.Sprintf("config saved to %s\n", configdir)
	return ret, nil
}

// loadConfiguration looks for the config file on disk, and loads the information
// if a file was found.
func loadConfiguration() error {
	configdir, err := getConfigdir()
	if err != nil {
		return err
	}

	// Return friendly err if file doesnt exist
	if _, err := os.Stat(configdir); os.IsNotExist(err) {
		return errors.New("No config found, try running the 'configure' command first")
	}

	file, err := os.Open(configdir)
	defer file.Close()
	if err != nil {
		return err
	}

	// Read the address, user, and password from the configuration file.
	lh := fmt.Sprintf("%slighthouse:", yamlSpace)
	user := fmt.Sprintf("%suser:", yamlSpace)
	password := fmt.Sprintf("%spassword:", yamlSpace)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, lh) {
			fields := strings.Split(line, ": ")
			lhaddress = fields[1]
		} else if strings.Contains(line, user) {
			fields := strings.Split(line, ": ")
			lhusername = fields[1]
		} else if strings.Contains(line, password) {
			fields := strings.Split(line, ": ")
			lhpassword = fields[1]
		}
	}
	return nil
}

func exitSuccess(msg string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', 1)
	fmt.Fprintf(w, msg)
	w.Flush()
	os.Exit(0)
}
func exitErr(err string) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// getAuthHeaders returns the headers required for an authenticated
// request to the lighthouse.
func setAuthHeaders(req *http.Request) {
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", authToken))
	req.Header.Set("Content-Type", "application/json")
}

// getURL returns a formatted URL from the lhaddress in config.
// Expects that version, and uri start with / and do not end with a /.
func getURL(uri string) string {
	return fmt.Sprintf("%s%s%s", lhaddress, version, uri)
}

// httpClient returns an http client. Seperated so we can modify the client
// if we need to.
func httpClient() *http.Client {
	// Ignore client certificate errors.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
	}
}

// getToken logs into the lighthouse instance and creates an Auth token for
// subsequent requests.
func getToken() (string, error) {
	var ret string
	type AuthReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	bodyRaw := AuthReq{
		Username: lhusername,
		Password: lhpassword,
	}
	body, err := json.Marshal(bodyRaw)
	if err != nil {
		return ret, err
	}
	url := getURL(sessionURI)
	req, err := buildReq(&body, url, http.MethodPost, false)
	if err != nil {
		return ret, err
	}

	rawResp, err := httpClient().Do(req)
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

// buildReq is a wrapper around the http.NewRequest function that ensures
// authenticated requests have the expected auth headers.
func buildReq(body *[]byte, url string, method string, auth bool) (*http.Request, error) {
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
		// We need a token before setting the headers.
		if authToken == "" {
			token, err := getToken()
			if err != nil {
				return nil, err
			}
			authToken = token
		}
		setAuthHeaders(req)
	}
	req.Close = true
	return req, nil
}

// addNode makes a POST request to the lighthouse including all of the new
// node information. This formats any error/response message to be friendly for
// the user.
func addNode(address, username, password, name, bundle string, approve bool) (string, error) {
	var ret string
	type NodeEnrollmentBody struct {
		Name        string `json:"name"`
		Address     string `json:"address"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Bundle      string `json:"bundle,omitempty"`
		Token       string `json:"token,omitempty"`
		Hostname    string `json:"hostname,omitempty"`
		AutoApprove bool   `json:"auto_approve"`
		CallHome    bool   `json:"call_home"`
	}
	type EnrollmentRequest struct {
		Enrollment NodeEnrollmentBody `json:"enrollment"`
	}

	// Build the request body.
	enrolBody := NodeEnrollmentBody{
		Address:     address,
		Name:        name,
		Username:    username,
		Password:    password,
		AutoApprove: !approve, // user specifies if they dont want it
		CallHome:    false,
	}
	if bundle != "" {
		enrolBody.Bundle = bundle
		enrolBody.Hostname = name
		enrolBody.CallHome = true
	}
	request := EnrollmentRequest{
		Enrollment: enrolBody,
	}
	reqJSON, err := json.Marshal(&request)
	if err != nil {
		return ret, err
	}
	url := getURL(nodeURI)

	// Make the POST request.
	req, err := buildReq(&reqJSON, url, http.MethodPost, true)
	rawResp, err := httpClient().Do(req)
	if err != nil {
		return ret, err
	}
	defer rawResp.Body.Close()
	if err := checkErr(rawResp); err != nil {
		return ret, err
	}

	return "Node added successfully\n", nil
}

// listNodes retrieves information for all nodes on the lighthouse.
// TODO: implement status, id, name filtering.
func listNodes() (string, error) {
	var ret string
	type NodeRuntimeStatus struct {
		ActionErr        string `json:"action_error_message"`
		ActionType       string `json:"action_type"`
		ConnectionStatus string `json:"connection_status"`
	}
	type NodesListBody struct {
		LHVPNAddress  string            `json:"lhvpn_address"`
		ID            string            `json:"id"`
		Status        string            `json:"status"`
		MacAddress    string            `json:"mac_address"`
		Model         string            `json:"model"`
		SerialNumber  string            `json:"serial_number"`
		Name          string            `json:"name"`
		Version       string            `json:"firmware_version"`
		RuntimeStatus NodeRuntimeStatus `json:"runtime_status"`
	}
	type NodesListResponse struct {
		Nodes []NodesListBody `json:"nodes"`
	}

	// Make the request
	url := getURL(nodeURI)
	req, err := buildReq(nil, url, http.MethodGet, true)
	rawResp, err := httpClient().Do(req)
	if err != nil {
		return ret, err
	}
	defer rawResp.Body.Close()

	if err := checkErr(rawResp); err != nil {
		return ret, err
	}
	body, err := ioutil.ReadAll(rawResp.Body)
	if err != nil {
		return ret, err
	}

	// Decode the response.
	var b NodesListResponse
	err = json.Unmarshal(body, &b)
	if err != nil {
		return ret, err
	}

	// Prettify the response for output.
	if len(b.Nodes) == 0 {
		ret = "No nodes to list\n"
		return ret, nil
	}
	var out bytes.Buffer
	out.WriteString("ID\tName\tModel\tStatus\tLHVPN.Address\tFW.Version\tConn.Status\tErrors\n")
	for _, v := range b.Nodes {
		out.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			v.ID,
			v.Name,
			v.Model,
			v.Status,
			v.LHVPNAddress,
			v.Version,
			v.RuntimeStatus.ConnectionStatus,
			v.RuntimeStatus.ActionErr,
		))
	}
	ret = out.String()
	return ret, err
}

// deleteNode attempts to delete the node provided with -i.
func deleteNode() (string, error) {
	var ret string

	// Make the request.
	uri := fmt.Sprintf("%s/%s", nodeURI, id)
	url := getURL(uri)
	req, err := buildReq(nil, url, http.MethodDelete, true)
	rawResp, err := httpClient().Do(req)
	if err != nil {
		return ret, err
	}
	if err := checkErr(rawResp); err != nil {
		return ret, err

	}

	// Confirm the node was deleted.
	if rawResp.StatusCode != 204 {
		return ret, errors.New("Node was not able to be deleted")
	}
	ret = "Node deletion process started\n"

	return ret, nil
}

// getSSHAddr returns a formatted address for the ssh connection to the
// lighthouse.
func getSSHAddr() string {
	// We only want the hostname of the LH.
	add := strings.Replace(lhaddress, "https://", "", 1)
	return fmt.Sprintf("%s:%v", add, sshPort)
}

// getShell puts the user into an ssh connection running the pmshell command
// on the lighthouse.
func getShell() (string, error) {
	var ret string

	// Start by making a new ssh session on the lighthouse.
	sshConfig := &ssh.ClientConfig{
		User: lhusername,
		Auth: []ssh.AuthMethod{
			ssh.Password(lhpassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // We're authing with credentials.
	}
	connection, err := ssh.Dial(sshConn, getSSHAddr(), sshConfig)
	if err != nil {
		return ret, fmt.Errorf("Failed to create a new shell session: %s", err)
	}
	session, err := connection.NewSession()
	if err != nil {
		return ret, fmt.Errorf("Failed to create a new shell session: %s", err)
	}
	defer session.Close()

	// We'll need to create a PTY on the lighthouse to run the command.
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 160, 80, modes); err != nil {
		return ret, fmt.Errorf("Failed to create a new shell session: %s", err)
	}

	// Pipe all stdout, stderr, stdin to/from the PTY.
	stdin, err := session.StdinPipe()
	if err != nil {
		return ret, fmt.Errorf("Failed to create a new shell session: %s", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return ret, fmt.Errorf("Failed to create a new shell session: %s", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return ret, fmt.Errorf("Failed to create a new shell session: %s", err)
	}

	// Keep them synchronised.
	go io.Copy(stdin, os.Stdin)
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	// We'll need to catch SIGINT and SIGKILL to ensure the ssh session is closed.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		<-c
		session.Close()
	}()

	// Now we can run the pmshell command
	ret = "Shell session completed\n"
	session.Run("pmshell")
	return ret, nil
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
