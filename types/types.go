package types

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
