package registry

import (
	"strings"
	"time"
)

type KiroAPIModel struct {
	ModelID        string
	ModelName      string
	Description    string
	RateMultiplier float64
	RateUnit       string
	MaxInputTokens int
}

var DefaultKiroThinkingSupport = &ThinkingSupport{
	Min:            1024,
	Max:            32000,
	ZeroAllowed:    true,
	DynamicAllowed: true,
}

const DefaultKiroContextLength = 200000
const DefaultKiroMaxCompletionTokens = 64000

func ConvertKiroAPIModels(kiroModels []*KiroAPIModel) []*ModelInfo {
	if len(kiroModels) == 0 {
		return nil
	}

	now := time.Now().Unix()
	result := make([]*ModelInfo, 0, len(kiroModels))

	for _, km := range kiroModels {
		if km == nil {
			continue
		}
		if km.ModelID == "" {
			continue
		}

		normalizedID := normalizeKiroModelID(km.ModelID)
		info := &ModelInfo{
			ID:                  normalizedID,
			Object:              "model",
			Created:             now,
			OwnedBy:             "aws",
			Type:                "kiro",
			DisplayName:         generateKiroDisplayName(km.ModelName, normalizedID),
			Description:         km.Description,
			ContextLength:       getKiroContextLength(km.MaxInputTokens),
			MaxCompletionTokens: DefaultKiroMaxCompletionTokens,
			ExecutionTarget:     km.ModelID,
			Thinking:            cloneKiroThinkingSupport(DefaultKiroThinkingSupport),
		}

		result = append(result, info)
	}

	return result
}

func normalizeKiroModelID(modelID string) string {
	if modelID == "" {
		return ""
	}

	return strings.TrimSpace(modelID)
}

func generateKiroDisplayName(modelName, normalizedID string) string {
	if modelName != "" {
		return "Kiro " + modelName
	}

	displayID := normalizedID
	words := strings.Split(displayID, "-")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return "Kiro " + strings.Join(words, " ")
}

func generateAgenticDescription(baseDescription string) string {
	if baseDescription == "" {
		return "Optimized for coding agents with chunked writes"
	}
	return baseDescription + " (Agentic mode: chunked writes)"
}

func getKiroContextLength(maxInputTokens int) int {
	if maxInputTokens > 0 {
		return maxInputTokens
	}
	return DefaultKiroContextLength
}

func cloneKiroThinkingSupport(ts *ThinkingSupport) *ThinkingSupport {
	if ts == nil {
		return nil
	}

	clone := &ThinkingSupport{
		Min:            ts.Min,
		Max:            ts.Max,
		ZeroAllowed:    ts.ZeroAllowed,
		DynamicAllowed: ts.DynamicAllowed,
	}
	if len(ts.Levels) > 0 {
		clone.Levels = make([]string, len(ts.Levels))
		copy(clone.Levels, ts.Levels)
	}
	return clone
}
