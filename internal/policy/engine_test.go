package policy

import (
	"testing"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection/pb"
)

func TestPolicyEvaluation(t *testing.T) {
	policies := []config.PolicyConfig{
		{
			Name:          "strict-ai",
			DefaultAction: "allow",
			OnDetection: map[string]string{
				"API_KEY": "block",
				"EMAIL":   "redact",
				"PERSON":  "redact",
			},
			MinimumConfidence: 0.70,
			Exceptions: []config.DestinationException{
				{
					Destination: "*.openai.com",
					Allow:       []string{"API_KEY"},
				},
			},
			FailureBehavior: config.FailureBehavior{
				InferenceUnavailable: "block",
				InferenceTimeout:     "block",
			},
		},
	}

	engine := NewEngine(policies)

	// Case 1: Person and Email -> Redact
	dets1 := []*pb.Detection{
		{
			Category:   "PERSON",
			Confidence: 0.85,
		},
		{
			Category:   "EMAIL",
			Confidence: 0.95,
		},
	}
	dec1, err := engine.Evaluate("strict-ai", "api.anthropic.com", dets1)
	if err != nil {
		t.Fatal(err)
	}
	if dec1.FinalAction != ActionRedact {
		t.Errorf("expected ActionRedact, got %v", dec1.FinalAction)
	}
	if len(dec1.RedactList) != 2 {
		t.Errorf("expected 2 redacted items, got %d", len(dec1.RedactList))
	}

	// Case 2: API_KEY sent to anthropic -> Block
	dets2 := []*pb.Detection{
		{
			Category:   "EMAIL",
			Confidence: 0.95,
		},
		{
			Category:   "API_KEY",
			Confidence: 0.99,
		},
	}
	dec2, err := engine.Evaluate("strict-ai", "api.anthropic.com", dets2)
	if err != nil {
		t.Fatal(err)
	}
	if dec2.FinalAction != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", dec2.FinalAction)
	}

	// Case 3: API_KEY sent to api.openai.com -> Exception triggers, email is redacted, not blocked
	dec3, err := engine.Evaluate("strict-ai", "api.openai.com", dets2)
	if err != nil {
		t.Fatal(err)
	}
	if dec3.FinalAction != ActionRedact {
		t.Errorf("expected ActionRedact with exception, got %v", dec3.FinalAction)
	}

	// Case 4: Confidence below minimum threshold is ignored
	dets4 := []*pb.Detection{
		{
			Category:   "API_KEY",
			Confidence: 0.55, // below 0.70
		},
	}
	dec4, err := engine.Evaluate("strict-ai", "api.anthropic.com", dets4)
	if err != nil {
		t.Fatal(err)
	}
	if dec4.FinalAction != ActionAllow {
		t.Errorf("expected ActionAllow due to low confidence, got %v", dec4.FinalAction)
	}

	// Case 5: Fail-closed verification
	actFail := engine.EvaluateFailure("strict-ai", FailureInferenceUnavailable)
	if actFail != ActionBlock {
		t.Errorf("expected ActionBlock for unavailable inference, got %v", actFail)
	}
}
