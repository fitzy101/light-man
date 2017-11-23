package types

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

type SmartgroupListBody struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Query string `json:"query"`
}

type NodesSmartgroupResponse struct {
	Smartgroups []SmartgroupListBody `json:"smartgroups"`
}

type SearchBody struct {
	ID string `json:"id"`
}

type SearchResponse struct {
	SearchIDs SearchBody `json:"search"`
}

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
