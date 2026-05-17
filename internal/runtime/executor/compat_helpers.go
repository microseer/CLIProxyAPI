package executor

// compat_helpers.go provides package-level aliases and wrappers for helper functions
// that the kiro and codebuddy executors (copied from CLIProxyAPIPlus) call via the
// legacy unexported names. These thin wrappers forward to the canonical helps.* package.

import (
	"context"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	"github.com/tiktoken-go/tokenizer"
)

// upstreamRequestLog is an alias for helps.UpstreamRequestLog.
type upstreamRequestLog = helps.UpstreamRequestLog

// maxScannerBufferSize is the maximum buffer size for SSE scanning (20MB).
const maxScannerBufferSize = 20_971_520

// usageReporter wraps helps.UsageReporter exposing lowercase method aliases used by
// copied Plus executor files.
type usageReporter struct {
	*helps.UsageReporter
}

// trackFailure is a lowercase alias for TrackFailure.
func (r *usageReporter) trackFailure(ctx context.Context, err *error) {
	r.UsageReporter.TrackFailure(ctx, err)
}

// publish is a lowercase alias for Publish.
func (r *usageReporter) publish(ctx context.Context, detail usage.Detail) {
	r.UsageReporter.Publish(ctx, detail)
}

// ensurePublished is a lowercase alias for EnsurePublished.
func (r *usageReporter) ensurePublished(ctx context.Context) {
	r.UsageReporter.EnsurePublished(ctx)
}

// publishFailure is a lowercase alias for PublishFailure.
// Accepts no error argument — emits a zero-value failure record (request counting only).
func (r *usageReporter) publishFailure(ctx context.Context) {
	r.UsageReporter.PublishFailure(ctx)
}

// newProxyAwareHTTPClient creates an HTTP client configured with proxy and uTLS settings.
func newProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	return helps.NewProxyAwareHTTPClient(ctx, cfg, auth, timeout)
}

// newUsageReporter creates a new usage reporter for tracking request metrics.
func newUsageReporter(ctx context.Context, provider, model string, auth *cliproxyauth.Auth) *usageReporter {
	return &usageReporter{helps.NewUsageReporter(ctx, provider, model, auth)}
}

// recordAPIRequest logs an upstream API request.
func recordAPIRequest(ctx context.Context, cfg *config.Config, info upstreamRequestLog) {
	helps.RecordAPIRequest(ctx, cfg, info)
}

// recordAPIResponseError records an upstream response error.
func recordAPIResponseError(ctx context.Context, cfg *config.Config, err error) {
	helps.RecordAPIResponseError(ctx, cfg, err)
}

// recordAPIResponseMetadata records upstream response metadata.
func recordAPIResponseMetadata(ctx context.Context, cfg *config.Config, statusCode int, headers http.Header) {
	helps.RecordAPIResponseMetadata(ctx, cfg, statusCode, headers)
}

// appendAPIResponseChunk records a response body chunk.
func appendAPIResponseChunk(ctx context.Context, cfg *config.Config, chunk []byte) {
	helps.AppendAPIResponseChunk(ctx, cfg, chunk)
}

// isHTTPSuccess returns true for 2xx status codes.
func isHTTPSuccess(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// parseOpenAIStreamUsage extracts usage data from an OpenAI SSE line.
func parseOpenAIStreamUsage(line []byte) (usage.Detail, bool) {
	return helps.ParseOpenAIStreamUsage(line)
}

// getTokenizer returns a tokenizer codec for the given model name.
func getTokenizer(model string) (tokenizer.Codec, error) {
	return helps.TokenizerForModel(model)
}

// countOpenAIChatTokens counts tokens in an OpenAI chat completions payload.
func countOpenAIChatTokens(enc tokenizer.Codec, payload []byte) (int64, error) {
	return helps.CountOpenAIChatTokens(enc, payload)
}

// countClaudeChatTokens counts tokens in a Claude API chat payload.
// Falls back to the OpenAI token counter since both use similar BPE encodings.
func countClaudeChatTokens(enc tokenizer.Codec, payload []byte) (int64, error) {
	return helps.CountOpenAIChatTokens(enc, payload)
}

// payloadRequestedModel extracts the originally requested model name from options.
func payloadRequestedModel(opts cliproxyexecutor.Options, fallback string) string {
	return helps.PayloadRequestedModel(opts, fallback)
}

// applyPayloadConfigWithRoot applies payload rules from the global config.
func applyPayloadConfigWithRoot(cfg *config.Config, model, protocol, root string, payload, original []byte, requestedModel string) []byte {
	return helps.ApplyPayloadConfigWithRoot(cfg, model, protocol, root, payload, original, requestedModel, "")
}

// summarizeErrorBody returns a concise summary of an HTTP error response body.
func summarizeErrorBody(contentType string, body []byte) string {
	return helps.SummarizeErrorBody(contentType, body)
}
