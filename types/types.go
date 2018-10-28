package types

type HttpsBody struct {
	ValidFrom string `json:"valid_from"`
	ValidTo string `json:"valid_to"`
	Certificate string `json:"cert"`
	Key string `json:"key"`
	CommonName string `json:"common_name"`
	State string `json:"state"`
	Locality string `json:"locality"`
	OrgUnit string `json:"org_unit"`
	Email string `json:"email"`
	Organization string `json:"organization"`
	KeyLength int `json:"key_length"`
}

type AlternateApiBody struct {
	Enabled bool `json:"enabled"`
}

type AlternateApiRequest struct {
	AlternateApi AlternateApiBody `json:"system_alternate_api"`
}

type AlternateApiResponse struct {
	AlternateApi AlternateApiBody `json:"system_alternate_api"`
}

type VersionBody struct {
	Firmware string `json:"firmware_version"`
	Api string `json:"rest_api_version"`
}

type VersionResponse struct {
	Version VersionBody `json:"system_version"`
}

type EndpointBody struct {
	ID string `json:"id"`
	VpnPort int `json:"vpn_port"`
	ApiPort int `json:"api_port"`
	Address string `json:"address"`
}

type EndpointListResponse struct {
	Endpoints []EndpointBody `json:"system_external_endpoints"`
}

type EndpointResponse struct {
	Endpoint EndpointBody `json:"system_external_endpoints"`
}

type EndpointRequest struct {
	Endpoint EndpointBody `json:"systemExternalEndpoint"`
}

type SystemTimeBody struct {
	Time string `json:"time"`
}

type SystemTimeRequest struct {
	Time SystemTimeBody `json:"time"`
}

type SystemTimeResponse struct {
	Time SystemTimeBody `json:"time"`
}

type SystemTimezoneBody struct {
	Timezone string `json:"timezone"`
}

type SystemTimezoneRequest struct {
	SystemTimezone SystemTimezoneBody `json:"system_timezone"`
}

type SystemTimezoneResponse struct {
	SystemTimezone SystemTimezoneBody `json:"system_timezone"`
}

type ManifestBody struct {
	URL string `json:"url"`
}

type ManifestResponse struct {
	Manifest ManifestBody `json:"system_global_manifest_link"`
}

type DefaultAddressBody struct {
	Address string `json:"address"`
}

type DefaultAddressResponse struct {
	DefaultAddress DefaultAddressBody `json:"os_default_external_address"`
}

type EnrollmentTokenBody struct {
	Token string `json:"token"`
}

type EnrollmentTokenRequest struct {
	EnrollmentToken EnrollmentTokenBody `json:"system_global_enrollment_token"`
}

type EnrollmentTokenResponse struct {
	EnrollmentToken EnrollmentTokenBody `json:"system_global_enrollment_token"`
}

type SshPortBody struct {
	Port int `json:"port"`
}

type SshPortResponse struct {
	SshPort SshPortBody `json:"system_ssh_port"`
}

type SshPortRequest struct {
	SshPort SshPortBody `json:"system_ssh_port"`
}

type CliSessionTimeoutBody struct {
	Timeout int `json:"timeout"`
}

type CliSessionTimeoutResponse struct {
	CliSessionTimeout CliSessionTimeoutBody `json:"system_cli_session_timeout"`
}

type CliSessionTimeoutRequest struct {
	CliSessionTimeout CliSessionTimeoutBody `json:"system_cli_session_timeout"`
}

type WebuiSessionTimeoutBody struct {
	Timeout int `json:"timeout"`
}

type WebuiSessionTimeoutResponse struct {
	WebuiSessionTimeout WebuiSessionTimeoutBody `json:"system_webui_session_timeout"`
}

type WebuiSessionTimeoutRequest struct {
	WebuiSessionTimeout WebuiSessionTimeoutBody `json:"system_webui_session_timeout"`
}

type SystemHostnameBody struct {
	Hostname string `json:"hostname"`
}

type SystemHostnameResponse struct {
	SystemHostname SystemHostnameBody `json:"system_hostname"`
}

type SystemHostnameRequest struct {
	SystemHostname SystemHostnameBody `json:"system_hostname"`
}

// NodeRuntimeStatus is the response body returned from the API.
type NodeRuntimeStatus struct {
	ActionErr        string `json:"action_error_message"`
	ActionType       string `json:"action_type"`
	ConnectionStatus string `json:"connection_status"`
}

// NodesListBody is the response body returned from the API.
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

// NodesListResponse is the response body returned from the API.
type NodesListResponse struct {
	Nodes []NodesListBody `json:"nodes"`
}

// SmartgroupListBody is the response body returned from the API.
type SmartgroupListBody struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Query string `json:"query"`
}

// NodesSmartgroupResponse is the response body returned from the API.
type NodesSmartgroupResponse struct {
	Smartgroups []SmartgroupListBody `json:"smartgroups"`
}

// SearchBody is the response body returned from the API.
type SearchBody struct {
	ID string `json:"id"`
}

// SearchResponse is the response body returned from the API.
type SearchResponse struct {
	SearchIDs SearchBody `json:"search"`
}

// NodeEnrollmentBody is the response body returned from the API.
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

// EnrollmentRequest is the response body returned from the API.
type EnrollmentRequest struct {
	Enrollment NodeEnrollmentBody `json:"enrollment"`
}
