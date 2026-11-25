package rocketim

// Capacity只包含计量和有界阶段。数值为规范十进制；未知用量为null，不能当作零。
type Capacity struct {
	Version       string              `json:"version"`
	Owner         string              `json:"owner"`
	ObservationID string              `json:"observation_id"`
	Consistency   string              `json:"consistency"`
	Scope         CapacityScope       `json:"scope"`
	Schema        string              `json:"schema"`
	Budgets       []CapacityBudget    `json:"budgets"`
	Cursors       *CapacityCursors    `json:"cursors"`
	Recovery      string              `json:"recovery"`
	Reserve       CapacityReserve     `json:"reserve"`
	Operations    []CapacityOperation `json:"operations"`
	Physical      CapacityUnavailable `json:"physical"`
	Remote        CapacityUnavailable `json:"remote"`
}
type CapacityScope struct {
	Service      string  `json:"service"`
	Conversation string  `json:"conversation"`
	Access       string  `json:"access"`
	Account      *string `json:"account"`
	Device       *string `json:"device"`
	Principal    *string `json:"principal"`
}
type CapacityBudget struct {
	Enforcement   string  `json:"enforcement"`
	Category      string  `json:"category"`
	Unit          string  `json:"unit"`
	State         string  `json:"state"`
	Used          *string `json:"used"`
	Limit         string  `json:"limit"`
	HardRemaining *string `json:"hard_remaining"`
	Reason        *string `json:"reason"`
}
type CapacityCursors struct {
	Tail            string `json:"tail"`
	Processed       string `json:"processed"`
	PendingMessages string `json:"pending_messages"`
	PendingControl  string `json:"pending_control"`
}
type CapacityReserve struct {
	State              string                     `json:"state"`
	ProtectedRemaining *string                    `json:"protected_remaining"`
	OrdinaryAvailable  *string                    `json:"ordinary_available"`
	Resources          []CapacityReservedResource `json:"resources"`
	Work               []CapacityReservedWork     `json:"work"`
}
type CapacityOperation struct {
	Operation string   `json:"operation"`
	State     string   `json:"state"`
	Blockers  []string `json:"blockers"`
}
type CapacityUnavailable struct {
	State    string `json:"state"`
	Reserved bool   `json:"reserved"`
}

type CapacityReservedResource struct {
	Category           string `json:"category"`
	ProtectedRemaining string `json:"protected_remaining"`
	OrdinaryAvailable  string `json:"ordinary_available"`
}
type CapacityReservedWork struct {
	Kind  string `json:"kind"`
	Count string `json:"count"`
}
