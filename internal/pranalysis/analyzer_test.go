package pranalysis

import (
	"context"
	"errors"
	"testing"

	"github.com/localenv/localenv/internal/githubapp"
)

type fakeReader map[string][]byte

func (r fakeReader) ReadFile(_ context.Context, _ githubapp.Credentials, _ int64, _, _, filename, ref string) ([]byte, error) {
	value, found := r[ref+":"+filename]
	if !found {
		return nil, githubapp.ErrNotFound
	}
	return value, nil
}

func TestAnalyzeComparesCompleteBaseAndHeadSchemas(t *testing.T) {
	reader := fakeReader{
		"head:localenv.yaml": []byte("version: 1\nfiles:\n  - schema: .env.example\n    target: .env.local\n"),
		"base:.env.example":  []byte("EXISTING=ignored\nOLD_KEY=ignored\n"),
		"head:.env.example":  []byte("EXISTING=ignored\nNEW_B=ignored\nNEW_A=ignored\n"),
	}
	result, err := Analyze(context.Background(), reader, githubapp.Credentials{}, 7, testPull())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Requirements) != 3 {
		t.Fatalf("requirements = %#v, want two additions and one removal", result.Requirements)
	}
	want := []struct{ key, state string }{{"NEW_A", StateMissing}, {"NEW_B", StateMissing}, {"OLD_KEY", StateRemoved}}
	for index, requirement := range result.Requirements {
		if requirement.KeyName != want[index].key || requirement.State != want[index].state {
			t.Errorf("requirement[%d] = %#v, want %s/%s", index, requirement, want[index].key, want[index].state)
		}
	}
}

func TestAnalyzeTreatsNewSchemaFileAsEmptyBase(t *testing.T) {
	reader := fakeReader{
		"head:localenv.yaml":       []byte("version: 1\nfiles:\n  - schema: config/.env.example\n    target: config/.env.local\n"),
		"head:config/.env.example": []byte("ADDED=non-secret-schema-default\n"),
	}
	result, err := Analyze(context.Background(), reader, githubapp.Credentials{}, 7, testPull())
	if err != nil || len(result.Requirements) != 1 || result.Requirements[0].KeyName != "ADDED" || result.Requirements[0].State != StateMissing {
		t.Fatalf("Analyze() = (%#v, %v), want one missing added key", result, err)
	}
}

func TestAnalyzeRejectsMissingHeadSchema(t *testing.T) {
	reader := fakeReader{"head:localenv.yaml": []byte("version: 1\nfiles:\n  - schema: .env.example\n    target: .env.local\n")}
	_, err := Analyze(context.Background(), reader, githubapp.Credentials{}, 7, testPull())
	if !errors.Is(err, githubapp.ErrNotFound) {
		t.Fatalf("Analyze() error = %v, want missing head schema", err)
	}
}

func testPull() githubapp.PullRequest {
	return githubapp.PullRequest{Number: 100, BaseSHA: "base", HeadSHA: "head", AuthorID: 5, Repository: githubapp.Repository{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main"}}
}
