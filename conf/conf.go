package conf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/fitzy101/light-man/client"
)

const (
	configfile = ".oglh"
	yamlSpace  = "  "
)

// GetConfigdir returns the filepath to the light-man configuration file.
func GetConfigdir() (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", err
	}
	config := fmt.Sprintf("%s/%s", user.HomeDir, configfile)
	return config, nil
}

// WriteConfig sets up the light-man configuration file.
func WriteConfig(address, username, password, token string) (string, error) {
	var ret string
	configdir, err := GetConfigdir()
	if err != nil {
		return ret, err
	}

	file, err := os.Create(configdir)
	defer file.Close()
	if err != nil {
		return ret, err
	}

	// We're using YAML for the configuration here.
	var fbuff bytes.Buffer
	fbuff.WriteString(fmt.Sprintf("lighthouse_configuration:\n"))
	fbuff.WriteString(fmt.Sprintf("%slighthouse: %s\n", yamlSpace, address))
	fbuff.WriteString(fmt.Sprintf("%suser: %s\n", yamlSpace, username))
	fbuff.WriteString(fmt.Sprintf("%spassword: %s\n", yamlSpace, password))
	fbuff.WriteString(fmt.Sprintf("%stoken: %s\n", yamlSpace, token))
	_, wErr := file.WriteString(fbuff.String())
	if wErr != nil {
		return ret, wErr
	}

	ret = configdir
	return ret, nil
}

// LoadConfiguration looks for the config file on disk, and loads the information
// if a file was found.
func LoadConfiguration() (string, string, string, string, error) {
	var lhaddress, lhusername, lhpassword, lhtoken string
	configdir, err := GetConfigdir()
	if err != nil {
		return lhaddress, lhusername, lhpassword, lhtoken, err
	}

	// Return friendly err if file doesnt exist
	if _, err := os.Stat(configdir); os.IsNotExist(err) {
		return lhaddress, lhusername, lhpassword, lhtoken, errors.New("No config found, try running the 'configure' command first")
	}

	file, err := os.Open(configdir)
	defer file.Close()
	if err != nil {
		return lhaddress, lhusername, lhpassword, lhtoken, err
	}

	// Read the address, user, and password from the configuration file.
	lh := fmt.Sprintf("%slighthouse:", yamlSpace)
	user := fmt.Sprintf("%suser:", yamlSpace)
	password := fmt.Sprintf("%spassword:", yamlSpace)
	token := fmt.Sprintf("%stoken:", yamlSpace)
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
		} else if strings.Contains(line, token) {
			fields := strings.Split(line, ": ")
			lhtoken = fields[1]
		}
	}

	// Check the token is still valid.
	client.LhToken = lhtoken
	client.LhUsername = lhusername
	client.LhPassword = lhpassword
	client.LhAddress = lhaddress
	if invalid, _ := client.CheckToken(); invalid {
		lhtoken, err = client.GetToken()
		client.LhToken = lhtoken

		// Write the new token to config.
		WriteConfig(lhaddress, lhusername, lhpassword, lhtoken)
	}

	return lhaddress, lhusername, lhpassword, lhtoken, err
}
