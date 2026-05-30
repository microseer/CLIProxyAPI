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

func GenerateAgenticVariants(models []*ModelInfo) []*ModelInfo {
	if len(models) == 0 {
		return nil
	}

	result := make([]*ModelInfo, 0, len(models)*2)
	for _, model := range models {
		if model == nil {
			continue
		}

		result = append(result, model)
		if strings.HasSuffix(model.ID, "-agentic") {
			continue
		}
		if model.ID == "kiro-auto" {
			continue
		}

		agenticModel := &ModelInfo{
			ID:                  model.ID + "-agentic",
			Object:              model.Object,
			Created:             model.Created,
			OwnedBy:             model.OwnedBy,
			Type:                model.Type,
			DisplayName:         model.DisplayName + " (Agentic)",
			Description:         generateAgenticDescription(model.Description),
			ContextLength:       model.ContextLength,
			MaxCompletionTokens: model.MaxCompletionTokens,
			ExecutionTarget:     model.ExecutionTarget,
			Thinking:            cloneKiroThinkingSupport(model.Thinking),
		}

		result = append(result, agenticModel)
	}

	return result
}

func MergeWithStaticMetadata(dynamicModels, staticModels []*ModelInfo) []*ModelInfo {
	if len(dynamicModels) == 0 && len(staticModels) == 0 {
		return nil
	}

	staticMap := make(map[string]*ModelInfo, len(staticModels))
	for _, sm := range staticModels {
		if sm != nil && sm.ID != "" {
			staticMap[sm.ID] = sm
		}
	}

	seenIDs := make(map[string]struct{})
	result := make([]*ModelInfo, 0, len(dynamicModels))
	for _, dm := range dynamicModels {
		if dm == nil || dm.ID == "" {
			continue
		}
		if _, seen := seenIDs[dm.ID]; seen {
			continue
		}
		seenIDs[dm.ID] = struct{}{}

		if sm, exists := staticMap[dm.ID]; exists {
			if sm.ExecutionTarget == "" && dm.ExecutionTarget != "" {
				merged := cloneModelInfo(sm)
				merged.ExecutionTarget = dm.ExecutionTarget
				result = append(result, merged)
			} else {
				result = append(result, sm)
			}
		} else {
			result = append(result, dm)
		}
	}

	return result
}

func normalizeKiroModelID(modelID string) string {
	if modelID == "" {
		return ""
	}

	modelID = strings.TrimSpace(modelID)
	normalized := strings.ReplaceAll(modelID, ".", "-")
	if !strings.HasPrefix(normalized, "kiro-") {
		normalized = "kiro-" + normalized
	}
	return normalized
}

func generateKiroDisplayName(modelName, normalizedID string) string {
	if modelName != "" {
		return "Kiro " + modelName
	}

	displayID := strings.TrimPrefix(normalizedID, "kiro-")
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
