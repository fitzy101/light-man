// light-man is a tool for communicating with an Opengear Lighthouse instance
// via cli, utilising the REST API. Currently implemented are:
// add, delete, list, and shell.
//
// Written with go 1.9, however would probably run on earlier versions.
// To compile, navigate to the source folder and type 'make'. You'll need to
// install the dependencies with `go get ./...`.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/fitzy101/light-man/client"
	"github.com/fitzy101/light-man/conf"
	"github.com/fitzy101/light-man/types"
	"golang.org/x/crypto/ssh"
)

var (
	// Lighthouse vars.
	lhaddress  string
	lhusername string
	lhpassword string
	lhtoken    string

	// Console Server vars.
	address    string
	username   string
	password   string
	name       string
	bundle     string
	noauto     bool
	log        bool
	id         string
	smartgroup string

	// Housekeeping vars.
	command string
)

const (
	dcommand    = "the command to run with light-man"
	daddress    = "URL of the Lighthouse instance"
	dnaddress   = "FQDN or IP Address of the node"
	dusername   = "user name for a Lighthouse user (default is 'root')"
	dpassword   = "password for the Lighthouse user (default is 'default')"
	dname       = "name of the node to add"
	dbundle     = "name of the enrollment bundle"
	dauto       = "indicates the node should NOT be auto-approved on enrollment"
	did         = "the identifier for a node - find with the list command"
	dsmartgroup = "the name of a smartgroup to filter the command"
	dlog        = "enable request logging to stdout"

	nodeURI   = "/nodes"
	searchURI = "/search/nodes"
	sgURI     = "/nodes/smartgroups"

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
	flag.StringVar(&smartgroup, "g", "", dsmartgroup)
	flag.BoolVar(&noauto, "no", false, dauto)
	flag.BoolVar(&log, "log", false, dlog)
}

func usage() string {
	var sbuff bytes.Buffer
	sbuff.WriteString("Usage: light-man -c [COMMAND] [OPTIONS]...\n")

	// configure
	sbuff.WriteString("\tconfigure: set up light-man with your Lighthouse credentials\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-a: %s\n", daddress))
	sbuff.WriteString(fmt.Sprintf("\t\t-u: %s\n", dusername))
	sbuff.WriteString(fmt.Sprintf("\t\t-p: %s\n", dpassword))

	// add
	sbuff.WriteString("\tadd: add a new node to the Lighthouse\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-a: %s\n", dnaddress))
	sbuff.WriteString(fmt.Sprintf("\t\t-u: %s\n", dusername))
	sbuff.WriteString(fmt.Sprintf("\t\t-p: %s\n", dpassword))
	sbuff.WriteString(fmt.Sprintf("\t\t-n: %s\n", dname))
	sbuff.WriteString(fmt.Sprintf("\t\t-no: %s\n", dauto))

	// list
	sbuff.WriteString("\tlist: list all nodes on the Lighthouse\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-g: %s\n", dsmartgroup))

	// delete
	sbuff.WriteString("\tdelete: delete a node from the Lighthouse\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-i: %s\n", did))

	// delete-all
	sbuff.WriteString("\tdelete-all: delete all nodes from the Lighthouse\n")
	sbuff.WriteString(fmt.Sprintf("\t\t-g: %s\n", dsmartgroup))

	// shell
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
	if log {
		client.LogLevel = client.LOGINFO
	}
	var msg string
	switch command {
	case "configure":
		client.LhAddress = address
		client.LhUsername = username
		client.LhPassword = password
		token, err := client.GetToken()
		if err != nil {
			return msg, err
		}

		msg, err := configure(address, username, password, token)
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
	case "delete-all":
		if err := loadConfiguration(); err != nil {
			return msg, err
		}
		msg, err := deleteAllNodes()
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

// configure sets up the light-man configuration file.
func configure(address, username, password, token string) (string, error) {
	var ret string
	configdir, err := conf.WriteConfig(address, username, password, token)
	if err != nil {
		return ret, err
	}

	ret = fmt.Sprintf("config saved to %s\n", configdir)
	return ret, nil
}

func loadConfiguration() error {
	add, user, pass, token, err := conf.LoadConfiguration()
	if err != nil {
		return err
	}

	// Setup the client package with the user data.
	lhaddress = add
	lhusername = user
	lhpassword = pass
	lhtoken = token
	client.LhAddress = lhaddress
	client.LhUsername = lhusername
	client.LhPassword = lhpassword
	client.LhToken = lhtoken
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

// addNode makes a POST request to the lighthouse including all of the new
// node information. This formats any error/response message to be friendly for
// the user.
func addNode(address, username, password, name, bundle string, approve bool) (string, error) {
	var ret string

	// Build the request body.
	enrolBody := types.NodeEnrollmentBody{
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
	request := types.EnrollmentRequest{
		Enrollment: enrolBody,
	}
	reqJSON, err := json.Marshal(&request)
	if err != nil {
		return ret, err
	}
	url, err := client.GetURL(nodeURI)
	if err != nil {
		return ret, err
	}

	req, err := client.BuildReq(&reqJSON, url, http.MethodPost, true)
	rawResp, err := client.HttpClient().Do(req)
	if err != nil {
		return ret, err
	}
	_, err = client.ParseReq(rawResp)
	if err != nil {
		return ret, err
	}

	return "Node added successfully\n", nil
}

// getAllNodes retrieves information for all nodes on the lighthouse.
func getAllNodes() (types.NodesListResponse, error) {
	var ret types.NodesListResponse

	// If a smartgroup name was specified, we need to perform a search first
	// and append it onto the URI.
	var url string
	var err error
	if smartgroup != "" {
		searchID, err := getSearchID()
		if err != nil {
			return ret, err
		}
		searchQ := client.Parameters{
			Name:  "searchId",
			Value: searchID,
		}
		url, err = client.GetURL(nodeURI, searchQ)
		if err != nil {
			return ret, err
		}
	} else {
		url, err = client.GetURL(nodeURI)
		if err != nil {
			return ret, err
		}
	}

	req, err := client.BuildReq(nil, url, http.MethodGet, true)
	rawResp, err := client.HttpClient().Do(req)
	if err != nil {
		return ret, err
	}
	body, err := client.ParseReq(rawResp)
	if err != nil {
		return ret, err
	}

	// Decode the response.
	err = json.Unmarshal(body, &ret)
	if err != nil {
		return ret, err
	}

	return ret, nil
}

// listNodes returns a formatted output of a list of all nodes on the lighthouse.
func listNodes() (string, error) {
	var ret string

	list, err := getAllNodes()
	if err != nil {
		return ret, err
	}

	// Prettify the response for output.
	if len(list.Nodes) == 0 {
		ret = "No nodes to list\n"
		return ret, nil
	}
	var out bytes.Buffer
	out.WriteString("ID\tName\tModel\tStatus\tLHVPN.Address\tFW.Version\tConn.Status\tErrors\n")
	for _, v := range list.Nodes {
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

	uri := fmt.Sprintf("%s/%s", nodeURI, id)
	url, err := client.GetURL(uri)
	if err != nil {
		return ret, err
	}
	req, err := client.BuildReq(nil, url, http.MethodDelete, true)
	rawResp, err := client.HttpClient().Do(req)
	if err != nil {
		return ret, err
	}
	if _, err := client.ParseReq(rawResp); err != nil {
		return ret, err
	}

	// Confirm the node was deleted.
	if rawResp.StatusCode != 204 {
		return ret, errors.New("Node was not able to be deleted")
	}
	ret = "Node deletion process started\n"

	return ret, nil
}

// deleteAllNodes attempts to delete all nodes enrolled in lighthouse.
func deleteAllNodes() (string, error) {
	var ret string

	// First we need all nodes, so we can get their id.
	list, err := getAllNodes()
	if err != nil {
		return ret, err
	}

	if len(list.Nodes) == 0 {
		ret = "No nodes to delete\n"
		return ret, nil
	}

	// Go through the list and delete all the nodes.
	for _, v := range list.Nodes {
		uri := fmt.Sprintf("%s/%s", nodeURI, v.ID)
		url, err := client.GetURL(uri)
		if err != nil {
			return ret, err
		}
		req, err := client.BuildReq(nil, url, http.MethodDelete, true)
		rawResp, err := client.HttpClient().Do(req)
		if err != nil {
			return ret, err
		}
		if _, err := client.ParseReq(rawResp); err != nil {
			return ret, err
		}

		// Confirm the node was deleted.
		if rawResp.StatusCode != 204 {
			return ret, fmt.Errorf("Node %s was not able to be deleted", v.ID)
		}
	}

	ret = fmt.Sprintf("Node deletion process started for %v node(s)\n", len(list.Nodes))
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

// getSearchID returns a searchID for a specified smartgroup.
func getSearchID() (string, error) {
	// Unfortunately there isn't a GET smartgroup by name endpoint, so we
	// need to enumerate them all to find the one we want.
	var ret string

	// Fetch all of the smart groups.
	url, err := client.GetURL(sgURI)
	if err != nil {
		return ret, err
	}
	req, err := client.BuildReq(nil, url, http.MethodGet, true)
	rawResp, err := client.HttpClient().Do(req)
	if err != nil {
		return ret, err
	}
	body, err := client.ParseReq(rawResp)
	if err != nil {
		return ret, err
	}
	var b types.NodesSmartgroupResponse
	err = json.Unmarshal(body, &b)
	if err != nil {
		return ret, err
	}

	// Now we need to find the smartgroupID, and from that the query.
	var query string
	for _, sg := range b.Smartgroups {
		if strings.Compare(sg.Name, smartgroup) == 0 {
			query = sg.Query
		}
	}
	if query == "" {
		return ret, nil
	}

	// Finally we can get a searchID.
	param := client.Parameters{
		Name:  "json",
		Value: query,
	}
	url, err = client.GetURL(searchURI, param)
	if err != nil {
		return ret, err
	}

	req, err = client.BuildReq(nil, url, http.MethodGet, true)
	rawResp, err = client.HttpClient().Do(req)
	if err != nil {
		return ret, err
	}
	body, err = client.ParseReq(rawResp)
	if err != nil {
		return ret, err
	}

	var bsearch types.SearchResponse
	err = json.Unmarshal(body, &bsearch)
	if err != nil {
		return ret, err
	}
	ret = bsearch.SearchIDs.ID

	return ret, nil
}
