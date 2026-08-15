import type { ReactNode } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  CircleAlert,
  CircleMinus,
  FileCode2,
  FolderGit2,
  GitBranch,
  GitPullRequest,
  KeyRound,
  ListChecks,
  Terminal,
} from "lucide-react";

import type { DashboardBootstrap, DashboardPullRequest, DashboardRepository } from "@/components/dashboard-shell";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";

function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function RequirementState({ state }: { state: string }) {
  if (state === "ready") {
    return <Badge variant="success"><CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5" />Ready</Badge>;
  }
  if (state === "missing") {
    return <Badge variant="warning"><CircleAlert aria-hidden="true" className="h-3.5 w-3.5" />Missing locally</Badge>;
  }
  return <Badge><CircleMinus aria-hidden="true" className="h-3.5 w-3.5" />Removed from schema</Badge>;
}

function RepositoryReadiness({ repository }: { repository: DashboardRepository }) {
  if (repository.missing_requirement_count > 0) {
    return <Badge variant="warning"><CircleAlert aria-hidden="true" className="h-3.5 w-3.5" />{pluralize(repository.missing_requirement_count, "missing requirement")}</Badge>;
  }
  if (repository.open_pull_request_count > 0) {
    return <Badge><GitPullRequest aria-hidden="true" className="h-3.5 w-3.5" />{pluralize(repository.open_pull_request_count, "open environment PR")}</Badge>;
  }
  return <Badge variant="success"><CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5" />No open environment PRs</Badge>;
}

function Metric({ icon: Icon, label, value }: { icon: typeof KeyRound; label: string; value: string | number }) {
  return (
    <div className="flex items-center gap-3 rounded-lg bg-muted p-3">
      <Icon aria-hidden="true" className="h-4 w-4 text-muted-foreground" />
      <div>
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        <p className="text-sm font-semibold tabular-nums">{value}</p>
      </div>
    </div>
  );
}

function PageHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return (
    <div className="mb-7 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{eyebrow}</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
      </div>
      {children}
    </div>
  );
}

function RepositoriesPage({ repositories }: { repositories: DashboardRepository[] }) {
  return (
    <>
      <PageHeading eyebrow="Operational dashboard" title="Repositories">
        <Badge><FolderGit2 aria-hidden="true" className="h-3.5 w-3.5" />{pluralize(repositories.length, "managed repository")}</Badge>
      </PageHeading>
      {repositories.length === 0 ? (
        <Card className="p-8 text-center sm:p-12">
          <FolderGit2 aria-hidden="true" className="mx-auto h-8 w-8 text-muted-foreground" />
          <h2 className="mt-4 text-lg font-semibold">No managed repositories yet</h2>
          <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">Install the GitHub App for a repository with a committed <code>localenv.yaml</code> to begin tracking its environment contract.</p>
        </Card>
      ) : (
        <div className="grid gap-3">
          {repositories.map((repository) => (
            <a key={`${repository.owner}/${repository.name}`} href={`/repos/${repository.owner}/${repository.name}`} className="group rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-success">
              <Card className="p-5 transition-colors group-hover:bg-muted/50 sm:p-6">
                <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <FolderGit2 aria-hidden="true" className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <h2 className="truncate text-lg font-semibold">{repository.owner}/{repository.name}</h2>
                    </div>
                    <p className="mt-2 flex items-center gap-2 text-sm text-muted-foreground"><GitBranch aria-hidden="true" className="h-4 w-4" />{repository.default_branch}</p>
                  </div>
                  <RepositoryReadiness repository={repository} />
                </div>
                <div className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-3">
                  <Metric icon={KeyRound} label="Managed keys" value={repository.managed_key_count} />
                  <Metric icon={GitPullRequest} label="Open PRs" value={repository.open_pull_request_count} />
                  <Metric icon={ListChecks} label="Revision" value={repository.revision} />
                </div>
              </Card>
            </a>
          ))}
        </div>
      )}
    </>
  );
}

function RepositoryPage({ repository }: { repository: DashboardRepository }) {
  return (
    <>
      <PageHeading eyebrow="Repository overview" title={`${repository.owner}/${repository.name}`}>
        <RepositoryReadiness repository={repository} />
      </PageHeading>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric icon={ListChecks} label="Baseline revision" value={repository.revision} />
        <Metric icon={KeyRound} label="Active key epoch" value={repository.active_key_epoch} />
        <Metric icon={KeyRound} label="Managed keys" value={repository.managed_key_count} />
        <Metric icon={GitPullRequest} label="Open environment PRs" value={repository.open_pull_request_count} />
      </div>

      <section className="mt-8" aria-labelledby="file-mappings-heading">
        <div className="mb-3 flex items-center gap-2"><FileCode2 aria-hidden="true" className="h-4 w-4 text-muted-foreground" /><h2 id="file-mappings-heading" className="text-base font-semibold">Managed file mappings</h2></div>
        <Card className="overflow-hidden">
          {repository.files.length === 0 ? <p className="p-5 text-sm text-muted-foreground">No file mappings have been discovered yet.</p> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[32rem] text-left text-sm">
                <thead className="bg-muted text-xs uppercase tracking-wide text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Schema</th><th className="px-5 py-3 font-medium">Local target</th></tr></thead>
                <tbody className="divide-y divide-border">{repository.files.map((file) => <tr key={`${file.schema_path}:${file.target_path}`}><td className="px-5 py-4 font-mono text-xs">{file.schema_path}</td><td className="px-5 py-4 font-mono text-xs">{file.target_path}</td></tr>)}</tbody>
              </table>
            </div>
          )}
        </Card>
      </section>

      <section className="mt-8" aria-labelledby="pulls-heading">
        <div className="mb-3 flex items-center gap-2"><GitPullRequest aria-hidden="true" className="h-4 w-4 text-muted-foreground" /><h2 id="pulls-heading" className="text-base font-semibold">Open environment-change PRs</h2></div>
        {repository.open_pull_requests.length === 0 ? <Card className="p-5 text-sm text-muted-foreground">No open environment-change PRs.</Card> : (
          <div className="grid gap-3">{repository.open_pull_requests.map((pull) => (
            <a key={pull.number} href={`/repos/${repository.owner}/${repository.name}/pulls/${pull.number}`} className="rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-success">
              <Card className="flex flex-col gap-3 p-5 transition-colors hover:bg-muted/50 sm:flex-row sm:items-center sm:justify-between">
                <div><p className="font-semibold">PR #{pull.number}</p><p className="mt-1 text-sm text-muted-foreground">{pull.state}</p></div>
                {pull.missing_requirement_count > 0 ? <Badge variant="warning"><CircleAlert aria-hidden="true" className="h-3.5 w-3.5" />{pluralize(pull.missing_requirement_count, "missing requirement")}</Badge> : <Badge variant="success"><CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5" />Requirements ready</Badge>}
              </Card>
            </a>
          ))}</div>
        )}
      </section>

      <Card className="mt-8 border-success/30 bg-success/10 p-5">
        <div className="flex gap-3"><Terminal aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0 text-success" /><div><h2 className="font-semibold">Secrets stay on your device</h2><p className="mt-1 text-sm text-muted-foreground">Use the CLI to initialize, sync, or resolve managed values. This dashboard shows only names, state, and repository metadata.</p></div></div>
      </Card>
    </>
  );
}

function PullRequestPage({ pullRequest, owner, repo }: { pullRequest: DashboardPullRequest; owner: string; repo: string }) {
  const missingCount = pullRequest.requirements.filter((requirement) => requirement.state === "missing").length;
  return (
    <>
      <a href={`/repos/${owner}/${repo}`} className="mb-5 inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-success"><ArrowLeft aria-hidden="true" className="h-4 w-4" />Back to {owner}/{repo}</a>
      <PageHeading eyebrow={`${owner}/${repo}`} title={`PR #${pullRequest.number}`}>
        {missingCount > 0 ? <Badge variant="warning"><CircleAlert aria-hidden="true" className="h-3.5 w-3.5" />Needs local resolution</Badge> : <Badge variant="success"><CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5" />Requirements ready</Badge>}
      </PageHeading>
      <Card className="p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-sm font-medium">Environment requirement status</p><p className="mt-1 text-sm text-muted-foreground">PR state: {pullRequest.state} · {pluralize(pullRequest.requirements.length, "requirement")}</p></div><RequirementState state={missingCount > 0 ? "missing" : "ready"} /></div>
      </Card>
      <section className="mt-8" aria-labelledby="requirements-heading">
        <div className="mb-3 flex items-center gap-2"><ListChecks aria-hidden="true" className="h-4 w-4 text-muted-foreground" /><h2 id="requirements-heading" className="text-base font-semibold">Requirements</h2></div>
        <Card className="overflow-hidden">
          {pullRequest.requirements.length === 0 ? <p className="p-5 text-sm text-muted-foreground">No environment requirements were detected for this PR.</p> : (
            <div className="overflow-x-auto"><table className="w-full min-w-[32rem] text-left text-sm"><thead className="bg-muted text-xs uppercase tracking-wide text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Key name</th><th className="px-5 py-3 font-medium">Status</th></tr></thead><tbody className="divide-y divide-border">{pullRequest.requirements.map((requirement, index) => <tr key={`${requirement.key_name}:${index}`}><td className="px-5 py-4 font-mono text-xs font-medium">{requirement.key_name}</td><td className="px-5 py-4"><RequirementState state={requirement.state} /></td></tr>)}</tbody></table></div>
          )}
        </Card>
      </section>
      <Card className="mt-8 border-warning/30 bg-warning/10 p-5"><div className="flex gap-3"><Terminal aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0 text-warning" /><div><h2 className="font-semibold">Resolve values with the CLI</h2><p className="mt-1 text-sm text-muted-foreground">For each missing requirement, run <code>localenv resolve</code> in your local repository. Values are encrypted locally and are never entered, displayed, or stored by this dashboard.</p></div></div></Card>
    </>
  );
}

export function RepositoryViews({ page }: { page: DashboardBootstrap }) {
  if (page.view.kind === "repositories") return <RepositoriesPage repositories={page.view.repositories} />;
  if (page.view.kind === "repository" && page.view.repository) return <RepositoryPage repository={page.view.repository} />;
  if (page.view.kind === "pull_request" && page.view.pull_request) return <PullRequestPage pullRequest={page.view.pull_request} owner={page.view.owner} repo={page.view.repo} />;
  return null;
}
