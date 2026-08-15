package sqlite

import (
	"context"
	"testing"

	"github.com/localenv/localenv/internal/githubapp"
)

func TestProcessGitHubWebhookIsIdempotentAndDiscoversRepositories(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event := githubapp.WebhookEvent{
		DeliveryID:           "delivery-test-1",
		EventType:            "installation_repositories",
		InstallationID:       42,
		InstallationOrgID:    9,
		InstallationOrgLogin: "acme",
		RepositoriesAdded:    []githubapp.Repository{{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main"}},
	}
	duplicate, err := store.ProcessGitHubWebhook(context.Background(), event)
	if err != nil || duplicate {
		t.Fatalf("first ProcessGitHubWebhook() = (%v, %v), want (false, nil)", duplicate, err)
	}
	duplicate, err = store.ProcessGitHubWebhook(context.Background(), event)
	if err != nil || !duplicate {
		t.Fatalf("second ProcessGitHubWebhook() = (%v, %v), want (true, nil)", duplicate, err)
	}
	repositories, err := store.DiscoveredRepositories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 1 || repositories[0].Owner != "acme" || repositories[0].Name != "api" {
		t.Fatalf("DiscoveredRepositories() = %#v, want acme/api", repositories)
	}
	var deliveries int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM webhook_deliveries WHERE github_delivery_id = 'delivery-test-1'`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Errorf("webhook deliveries = %d, want 1", deliveries)
	}
}

func TestFailedWebhookDeliveryCanBeRetried(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event := githubapp.WebhookEvent{DeliveryID: "delivery-retry-1", EventType: "ping"}
	if duplicate, err := store.ProcessGitHubWebhook(context.Background(), event); err != nil || duplicate {
		t.Fatalf("initial ProcessGitHubWebhook() = (%v, %v), want (false, nil)", duplicate, err)
	}
	if err := store.MarkGitHubWebhookFailed(context.Background(), event.DeliveryID); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := store.ProcessGitHubWebhook(context.Background(), event); err != nil || duplicate {
		t.Fatalf("retried ProcessGitHubWebhook() = (%v, %v), want (false, nil)", duplicate, err)
	}
}
