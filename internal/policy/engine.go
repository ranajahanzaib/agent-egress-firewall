package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection/pb"
)

type Action string

const (
	ActionAllow  Action = "allow"
	ActionRedact Action = "redact"
	ActionBlock  Action = "block"
)

type Decision struct {
	FinalAction Action
	Reason      string
	Detections  []*EvaluatedDetection
	RedactList  []*pb.Detection
	BlockList   []*pb.Detection
	AllowedList []*pb.Detection
}

type EvaluatedDetection struct {
	Detection *pb.Detection
	Action    Action
	Reason    string
}

type FailureType string

const (
	FailureInferenceUnavailable FailureType = "inference_unavailable"
	FailureInferenceTimeout     FailureType = "inference_timeout"
	FailureMalformedPayload     FailureType = "malformed_payload"
	FailureUnsupportedContent   FailureType = "unsupported_content"
	FailureOversizedPayload     FailureType = "oversized_payload"
)

type Engine struct {
	policies map[string]config.PolicyConfig
}

func NewEngine(policies []config.PolicyConfig) *Engine {
	m := make(map[string]config.PolicyConfig)
	for _, p := range policies {
		m[p.Name] = p
	}
	return &Engine{policies: m}
}

func (e *Engine) GetPolicy(name string) (config.PolicyConfig, bool) {
	p, ok := e.policies[name]
	return p, ok
}

// Evaluate evaluates a set of detections against the named policy for a destination.
func (e *Engine) Evaluate(policyName string, destinationHost string, detections []*pb.Detection) (*Decision, error) {
	policy, ok := e.policies[policyName]
	if !ok {
		return nil, fmt.Errorf("policy '%s' not found", policyName)
	}

	minConf := policy.MinimumConfidence
	if minConf <= 0.0 {
		minConf = 0.50
	}

	decision := &Decision{
		FinalAction: ActionAllow,
		Detections:  []*EvaluatedDetection{},
		RedactList:  []*pb.Detection{},
		BlockList:   []*pb.Detection{},
		AllowedList: []*pb.Detection{},
	}

	// Set baseline default
	switch strings.ToLower(policy.DefaultAction) {
	case "block":
		decision.FinalAction = ActionBlock
	case "redact":
		decision.FinalAction = ActionRedact
	default:
		decision.FinalAction = ActionAllow
	}

	var hasBlock bool
	var hasRedact bool

	for _, det := range detections {
		if det.Confidence < minConf {
			decision.Detections = append(decision.Detections, &EvaluatedDetection{
				Detection: det,
				Action:    ActionAllow,
				Reason:    fmt.Sprintf("confidence %.2f below threshold %.2f", det.Confidence, minConf),
			})
			decision.AllowedList = append(decision.AllowedList, det)
			continue
		}

		// Check destination exceptions
		if e.isDestinationException(policy, destinationHost, det.Category) {
			decision.Detections = append(decision.Detections, &EvaluatedDetection{
				Detection: det,
				Action:    ActionAllow,
				Reason:    fmt.Sprintf("destination exception for host '%s' allows category '%s'", destinationHost, det.Category),
			})
			decision.AllowedList = append(decision.AllowedList, det)
			continue
		}

		// Look up action for category in on_detection map
		actionStr, exists := policy.OnDetection[det.Category]
		if !exists {
			// Fallback to case-insensitive or default
			for k, v := range policy.OnDetection {
				if strings.EqualFold(k, det.Category) {
					actionStr = v
					exists = true
					break
				}
			}
		}

		var act Action
		if exists {
			switch strings.ToLower(actionStr) {
			case "block":
				act = ActionBlock
			case "redact":
				act = ActionRedact
			default:
				act = ActionAllow
			}
		} else {
			act = decision.FinalAction
		}

		decision.Detections = append(decision.Detections, &EvaluatedDetection{
			Detection: det,
			Action:    act,
			Reason:    fmt.Sprintf("rule for category '%s'", det.Category),
		})

		switch act {
		case ActionBlock:
			hasBlock = true
			decision.BlockList = append(decision.BlockList, det)
		case ActionRedact:
			hasRedact = true
			decision.RedactList = append(decision.RedactList, det)
		case ActionAllow:
			decision.AllowedList = append(decision.AllowedList, det)
		}
	}

	// Precedence: BLOCK > REDACT > ALLOW
	if hasBlock {
		decision.FinalAction = ActionBlock
		var blockedCategories []string
		for _, b := range decision.BlockList {
			blockedCategories = append(blockedCategories, b.Category)
		}
		decision.Reason = fmt.Sprintf("blocked due to sensitive categories: %s", strings.Join(blockedCategories, ", "))
	} else if hasRedact {
		decision.FinalAction = ActionRedact
		decision.Reason = fmt.Sprintf("redacting %d sensitive entities", len(decision.RedactList))
	} else {
		decision.FinalAction = ActionAllow
		decision.Reason = "request permitted by policy"
	}

	return decision, nil
}

// EvaluateFailure determines the action to take when an operational failure occurs.
func (e *Engine) EvaluateFailure(policyName string, failType FailureType) Action {
	policy, ok := e.policies[policyName]
	if !ok {
		// Strict fail-closed default
		return ActionBlock
	}

	var behavior string
	switch failType {
	case FailureInferenceUnavailable:
		behavior = policy.FailureBehavior.InferenceUnavailable
	case FailureInferenceTimeout:
		behavior = policy.FailureBehavior.InferenceTimeout
	case FailureMalformedPayload:
		behavior = policy.FailureBehavior.MalformedPayload
	case FailureUnsupportedContent:
		behavior = policy.FailureBehavior.UnsupportedContent
	case FailureOversizedPayload:
		behavior = policy.FailureBehavior.OversizedPayload
	}

	if strings.EqualFold(behavior, "allow") {
		return ActionAllow
	}

	// Default to block (fail-closed)
	return ActionBlock
}

func (e *Engine) isDestinationException(policy config.PolicyConfig, host string, category string) bool {
	// Strip port from host if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	for _, exc := range policy.Exceptions {
		destPattern := exc.Destination
		matched, _ := filepath.Match(destPattern, host)
		if !matched && strings.HasPrefix(destPattern, "*.") {
			suffix := destPattern[1:]
			matched = strings.HasSuffix(host, suffix)
		}
		if matched || destPattern == host {
			for _, allowedCat := range exc.Allow {
				if strings.EqualFold(allowedCat, category) {
					return true
				}
			}
		}
	}
	return false
}
