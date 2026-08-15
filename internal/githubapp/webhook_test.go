package githubapp

import "testing"

func TestParseWebhookExtractsPullRequestLifecycleMetadata(t *testing.T) {
	payload := []byte(`{"action":"closed","number":100,"installation":{"id":7,"account":{"id":2,"login":"acme"}},"repository":{"id":17,"name":"api","owner":{"login":"acme"},"default_branch":"main"},"pull_request":{"head":{"sha":"head"},"base":{"sha":"base"},"user":{"id":5},"merged":true,"merged_at":"2026-08-15T12:00:00Z"}}`)
	event, err := ParseWebhook("pull_request", "delivery-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if event.PullRequest == nil || event.PullRequest.State != "merged" || event.PullRequest.Number != 100 || event.PullRequest.Repository.GitHubRepoID != 17 || event.PullRequest.MergedAt == nil {
		t.Fatalf("PullRequest = %#v, want merged lifecycle metadata", event.PullRequest)
	}
}

func TestParseWebhookRejectsIncompletePullRequest(t *testing.T) {
	payload := []byte(`{"action":"opened","installation":{"id":7,"account":{"id":2,"login":"acme"}}}`)
	if _, err := ParseWebhook("pull_request", "delivery-1", payload); err == nil {
		t.Fatal("ParseWebhook() accepted incomplete pull request")
	}
}
