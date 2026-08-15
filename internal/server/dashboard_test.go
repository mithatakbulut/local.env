package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/internal/store/sqlite"
)

func TestDashboardViewForPageUsesOnlyRepositoryReadinessMetadata(t *testing.T) {
	pull := sqlite.DashboardPullRequest{
		Number: 17,
		State:  "open",
		Requirements: []pranalysis.Requirement{{
			FileID:     "file:D3_INTERNAL_ONLY",
			SchemaPath: "private-schema-path",
			TargetPath: "private-target-path",
			KeyName:    "D3_PUBLIC_KEY_NAME",
			State:      pranalysis.StateMissing,
		}},
	}
	view := dashboardViewForPage(dashboardPage{PullRequest: &pull, Owner: "acme", Repo: "api"})
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, want := range []string{`"kind":"pull_request"`, `"key_name":"D3_PUBLIC_KEY_NAME"`, `"state":"missing"`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard view missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"D3_INTERNAL_ONLY", "private-schema-path", "private-target-path", "ciphertext", "wrapped_rek", "secret_value"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("dashboard view exposed forbidden data %q: %s", forbidden, body)
		}
	}
}

func TestDashboardRepositoryViewIncludesSafeReadinessCounts(t *testing.T) {
	view := dashboardRepositoryViewFor(sqlite.DashboardRepository{
		Owner: "acme", Name: "api", DefaultBranch: "main", ActiveKeyEpoch: 3,
		Revision: 8, ManagedKeyCount: 4, OpenPullRequestCnt: 2, MissingRequirementCnt: 1,
	})
	if view.Owner != "acme" || view.ManagedKeyCount != 4 || view.OpenPullRequestCount != 2 || view.MissingRequirementCount != 1 {
		t.Fatalf("dashboard repository view = %#v", view)
	}
	if view.Files == nil || view.OpenPullRequests == nil {
		t.Fatalf("empty collections must be JSON arrays: %#v", view)
	}
}

func TestDashboardViewForEmptyRepositoryListUsesReactEmptyState(t *testing.T) {
	view := dashboardViewForPage(dashboardPage{RepositoryList: true})
	if view.Kind != "repositories" || view.Repositories == nil || len(view.Repositories) != 0 {
		t.Fatalf("empty repository dashboard view = %#v", view)
	}
}

func TestDashboardOperationalViewsUseOnlyAllowlistedMetadata(t *testing.T) {
	revokedAt := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC)
	devices := dashboardViewForPage(dashboardPage{DeviceList: true, Devices: []sqlite.DashboardDevice{{
		ID: "device-d4", GitHubLogin: "developer", Name: "laptop", Fingerprint: "sha256:d4", CreatedAt: revokedAt.Add(-time.Hour), LastSeenAt: revokedAt, RevokedAt: &revokedAt,
	}}})
	encodedDevices, err := json.Marshal(devices)
	if err != nil {
		t.Fatal(err)
	}
	deviceBody := string(encodedDevices)
	for _, want := range []string{`"kind":"devices"`, `"github_login":"developer"`, `"revoked_at":"2026-08-15T12:00:00Z"`} {
		if !strings.Contains(deviceBody, want) {
			t.Errorf("device view missing %q: %s", want, deviceBody)
		}
	}
	for _, forbidden := range []string{"public_recipient", "wrapped_rek", "ciphertext", "secret_value"} {
		if strings.Contains(deviceBody, forbidden) {
			t.Errorf("device view exposed forbidden data %q: %s", forbidden, deviceBody)
		}
	}

	audit := dashboardViewForPage(dashboardPage{AuditList: true, AuditEvents: []dashboardAuditEvent{{
		AuditEvent: sqlite.AuditEvent{EventType: "device.revoked", ActorUserID: "private-user-id", ActorDeviceID: "device-d4", RepositoryID: "private-repository-id", CreatedAt: revokedAt},
		Metadata:   []dashboardMetadata{{Key: "target_device_id", Value: "device-d4"}},
	}}})
	encodedAudit, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	auditBody := string(encodedAudit)
	for _, want := range []string{`"kind":"audit"`, `"event_type":"device.revoked"`, `"target_device_id"`} {
		if !strings.Contains(auditBody, want) {
			t.Errorf("audit view missing %q: %s", want, auditBody)
		}
	}
	for _, forbidden := range []string{"private-user-id", "private-repository-id", "ciphertext", "secret_value"} {
		if strings.Contains(auditBody, forbidden) {
			t.Errorf("audit view exposed forbidden data %q: %s", forbidden, auditBody)
		}
	}
}

func TestDashboardSetupViewRetainsNormalCSRFProtectedHandoff(t *testing.T) {
	view := dashboardViewForSetup(setupPage{CSRFToken: "csrf-d4-test", Organizations: []githubapp.Organization{{ID: 7, Login: "acme"}}})
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, want := range []string{`"kind":"setup"`, `"state":"organization_selection"`, `"csrf_token":"csrf-d4-test"`, `"id":7`, `"login":"acme"`} {
		if !strings.Contains(body, want) {
			t.Errorf("setup view missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"oauth_token", "private_key", "client_secret", "ciphertext", "wrapped_rek"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("setup view exposed forbidden data %q: %s", forbidden, body)
		}
	}
}
