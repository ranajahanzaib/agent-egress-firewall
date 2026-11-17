package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection"
	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection/pb"
)

type GroundTruth struct {
	Category string `json:"category"`
	Text     string `json:"text"`
}

type EvalItem struct {
	ID       string        `json:"id"`
	Language string        `json:"language"`
	Text     string        `json:"text"`
	Expected []GroundTruth `json:"expected"`
}

type MetricCounter struct {
	TP int
	FP int
	FN int
}

func (m *MetricCounter) Precision() float64 {
	if m.TP+m.FP == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(m.TP+m.FP)
}

func (m *MetricCounter) Recall() float64 {
	if m.TP+m.FN == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(m.TP+m.FN)
}

func (m *MetricCounter) F1() float64 {
	p := m.Precision()
	r := m.Recall()
	if p+r == 0 {
		return 0.0
	}
	return 2 * p * r / (p + r)
}

func main() {
	datasetPath := "tests/fixtures/eval_dataset.json"
	data, err := os.ReadFile(datasetPath)
	if err != nil {
		log.Fatalf("Failed to read dataset: %v", err)
	}

	var items []EvalItem
	if err := json.Unmarshal(data, &items); err != nil {
		log.Fatalf("Failed to parse dataset: %v", err)
	}

	client, err := inspection.NewClient("127.0.0.1:50051")
	if err != nil {
		log.Fatalf("Inference connection failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	patterns := []*pb.PatternDefinition{
		{
			Name:       "ACCOUNT_NUM",
			Category:   "ACCOUNT_NUMBER",
			Regex:      `\bACCT-[A-Z0-9]{8}\b`,
			Confidence: 1.0,
			Enabled:    true,
		},
		{
			Name:       "PROJ_TOKEN",
			Category:   "INTERNAL_PROJECT",
			Regex:      `\bproject-[a-z0-9_-]{6,}\b`,
			Confidence: 0.95,
			Enabled:    true,
		},
	}

	runEvaluationMode("COMBINED (GLiNER + Patterns)", client, ctx, items, patterns, true, true)
	runEvaluationMode("DETERMINISTIC PATTERNS ONLY", client, ctx, items, patterns, false, true)
	runEvaluationMode("GLiNER ML ONLY", client, ctx, items, nil, true, false)
}

func runEvaluationMode(
	modeName string,
	client *inspection.Client,
	ctx context.Context,
	items []EvalItem,
	patterns []*pb.PatternDefinition,
	enableML bool,
	enablePatterns bool,
) {
	fmt.Printf("\n======================================================\n")
	fmt.Printf(" EVALUATION REPORT: %s\n", modeName)
	fmt.Printf("======================================================\n")

	totalMetrics := &MetricCounter{}
	byCategory := make(map[string]*MetricCounter)
	byLang := make(map[string]*MetricCounter)

	for _, item := range items {
		if byLang[item.Language] == nil {
			byLang[item.Language] = &MetricCounter{}
		}

		resp, err := client.Scan(ctx, &pb.ScanRequest{
			RequestId: "eval_" + item.ID,
			Fields: []*pb.ScanField{
				{
					FieldId: item.ID,
					Text:    item.Text,
				},
			},
			Patterns: patterns,
			Options: &pb.ScanOptions{
				EnableMl:             enableML,
				EnablePatterns:       enablePatterns,
				DefaultMinConfidence: 0.50,
			},
		})
		if err != nil {
			log.Printf("Item %s scan failed: %v", item.ID, err)
			continue
		}

		matchedExpected := make([]bool, len(item.Expected))

		for _, det := range resp.Detections {
			cat := det.Category
			if byCategory[cat] == nil {
				byCategory[cat] = &MetricCounter{}
			}

			// Check if detection matches an expected ground truth
			matched := false
			for i, exp := range item.Expected {
				if !matchedExpected[i] && strings.EqualFold(exp.Category, cat) &&
					(strings.Contains(item.Text, exp.Text) && strings.Contains(exp.Text, det.Text) || strings.Contains(det.Text, exp.Text)) {
					matchedExpected[i] = true
					matched = true
					break
				}
			}

			if matched {
				totalMetrics.TP++
				byCategory[cat].TP++
				byLang[item.Language].TP++
			} else {
				totalMetrics.FP++
				byCategory[cat].FP++
				byLang[item.Language].FP++
			}
		}

		for i, exp := range item.Expected {
			if !matchedExpected[i] {
				cat := exp.Category
				if byCategory[cat] == nil {
					byCategory[cat] = &MetricCounter{}
				}
				totalMetrics.FN++
				byCategory[cat].FN++
				byLang[item.Language].FN++
			}
		}
	}

	fmt.Printf("OVERALL METRICS:\n")
	fmt.Printf("  Precision: %.3f (%d TP, %d FP)\n", totalMetrics.Precision(), totalMetrics.TP, totalMetrics.FP)
	fmt.Printf("  Recall:    %.3f (%d TP, %d FN)\n", totalMetrics.Recall(), totalMetrics.TP, totalMetrics.FN)
	fmt.Printf("  F1 Score:  %.3f\n\n", totalMetrics.F1())

	fmt.Printf("BY CATEGORY BREAKDOWN:\n")
	fmt.Printf("  %-20s %-8s %-8s %-8s %-8s\n", "Category", "Prec", "Recall", "F1", "TP/FP/FN")
	fmt.Printf("  --------------------------------------------------------\n")
	for cat, m := range byCategory {
		fmt.Printf("  %-20s %-8.2f %-8.2f %-8.2f %d/%d/%d\n",
			cat, m.Precision(), m.Recall(), m.F1(), m.TP, m.FP, m.FN)
	}

	fmt.Printf("\nBY LANGUAGE BREAKDOWN:\n")
	fmt.Printf("  %-10s %-8s %-8s %-8s %-8s\n", "Language", "Prec", "Recall", "F1", "TP/FP/FN")
	fmt.Printf("  --------------------------------------------------------\n")
	for lang, m := range byLang {
		fmt.Printf("  %-10s %-8.2f %-8.2f %-8.2f %d/%d/%d\n",
			lang, m.Precision(), m.Recall(), m.F1(), m.TP, m.FP, m.FN)
	}
}
