import { formatDistanceToNowStrict } from "date-fns";
import InfiniteScroll from "react-infinite-scroll-component";
import { useCallback, useState, type ReactNode } from "react";
import {
  CheckCircle2,
  CircleAlert,
  CircleMinus,
  ExternalLink,
  Github,
  History,
  Laptop,
  Link2,
  MonitorCog,
  ShieldCheck,
  Terminal,
} from "lucide-react";

import type { DashboardAuditEvent, DashboardAuditPage, DashboardBootstrap, DashboardDevice, DashboardSetup } from "@/components/dashboard-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

function PageHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return <div className="mb-7 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-sm font-medium text-muted-foreground">{eyebrow}</p><h1 className="mt-1 text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1></div>{children}</div>;
}

function timestamp(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? "—" : parsed.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function relativeTimestamp(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return "—";
  return formatDistanceToNowStrict(parsed, { addSuffix: true })
    .replace(/^1 minute\b/, "1 min")
    .replace(/^(\d+) minutes\b/, "$1 mins");
}

function DeviceState({ device }: { device: DashboardDevice }) {
  if (device.revoked_at) return <Badge variant="warning"><CircleMinus aria-hidden="true" className="h-3.5 w-3.5" />Revoked</Badge>;
  if (device.has_key) return <Badge variant="success"><CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5" />Active with key access</Badge>;
  return <Badge><CircleAlert aria-hidden="true" className="h-3.5 w-3.5" />Active, awaiting access</Badge>;
}

function DevicesPage({ devices }: { devices: DashboardDevice[] }) {
  return <>
    <PageHeading eyebrow="Repository-key access" title="Devices"><Badge><Laptop aria-hidden="true" className="h-3.5 w-3.5" />{devices.length} registered devices</Badge></PageHeading>
    <p className="mb-6 max-w-2xl text-sm text-muted-foreground">Device identities and repository-key access are managed through the CLI. Revoked devices no longer have repository-key access.</p>
    <Card className="overflow-hidden">
      {devices.length === 0 ? <div className="p-8 text-center sm:p-12"><Laptop aria-hidden="true" className="mx-auto h-8 w-8 text-muted-foreground" /><h2 className="mt-4 text-lg font-semibold">No devices registered</h2><p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">A developer’s device appears here after they sign in with <code>localenv</code>.</p></div> : <div className="overflow-x-auto"><table className="w-full min-w-[48rem] text-left text-sm"><thead className="bg-muted text-xs uppercase tracking-wide text-muted-foreground"><tr><th className="px-5 py-3 font-medium">User and device</th><th className="px-5 py-3 font-medium">Fingerprint</th><th className="px-5 py-3 font-medium">Access</th><th className="px-5 py-3 font-medium">Last seen</th></tr></thead><tbody className="divide-y divide-border">{devices.map((device) => <tr key={device.id}><td className="px-5 py-4"><p className="font-medium">{device.name}</p><p className="mt-1 text-xs text-muted-foreground">{device.github_login} · Registered {timestamp(device.created_at)}</p></td><td className="px-5 py-4 font-mono text-xs">{device.fingerprint}</td><td className="px-5 py-4"><DeviceState device={device} /></td><td className="px-5 py-4 text-xs text-muted-foreground">{device.revoked_at ? `Revoked ${timestamp(device.revoked_at)}` : timestamp(device.last_seen_at)}</td></tr>)}</tbody></table></div>}
    </Card>
  </>;
}

function Metadata({ event }: { event: DashboardAuditEvent }) {
  if (event.metadata.length === 0) return <span className="text-xs text-muted-foreground">No additional metadata</span>;
  return <div className="flex flex-wrap gap-1.5">{event.metadata.map(({ key, value }) => <span key={`${key}:${value}`} className="rounded-md bg-muted px-2 py-1 font-mono text-xs"><span className="text-muted-foreground">{key}=</span>{value}</span>)}</div>;
}

function isAuditPage(value: unknown): value is DashboardAuditPage {
  if (!value || typeof value !== "object") return false;
  const page = value as Partial<DashboardAuditPage>;
  return Array.isArray(page.events) && page.events.every((event) => Boolean(event) && typeof event === "object" && typeof (event as DashboardAuditEvent).event_type === "string" && typeof (event as DashboardAuditEvent).actor_device_id === "string" && typeof (event as DashboardAuditEvent).created_at === "string" && Array.isArray((event as DashboardAuditEvent).metadata) && (event as DashboardAuditEvent).metadata.every((metadata) => Boolean(metadata) && typeof metadata === "object" && typeof metadata.key === "string" && typeof metadata.value === "string")) && (page.next_cursor === undefined || typeof page.next_cursor === "string");
}

function AuditPage({ initialEvents, initialNextCursor }: { initialEvents: DashboardAuditEvent[]; initialNextCursor?: string }) {
  const [events, setEvents] = useState(initialEvents);
  const [nextCursor, setNextCursor] = useState(initialNextCursor);
  const [canLoadMore, setCanLoadMore] = useState(Boolean(initialNextCursor));
  const [loadError, setLoadError] = useState(false);

  const loadMore = useCallback(async () => {
    if (!nextCursor) return;
    try {
      setLoadError(false);
      const response = await fetch(`/api/v1/dashboard/audit?cursor=${encodeURIComponent(nextCursor)}`, { credentials: "same-origin", headers: { Accept: "application/json" } });
      const page: unknown = await response.json();
      if (!response.ok || !isAuditPage(page)) throw new Error("audit page unavailable");
      setEvents((current) => [...current, ...page.events]);
      setNextCursor(page.next_cursor);
      setCanLoadMore(Boolean(page.next_cursor));
    } catch {
      setLoadError(true);
      setCanLoadMore(false);
    }
  }, [nextCursor]);

  return <>
    <PageHeading eyebrow="Metadata-only event trail" title="Audit"><Badge><History aria-hidden="true" className="h-3.5 w-3.5" />{events.length} loaded</Badge></PageHeading>
    <Card className="overflow-hidden">
      {events.length === 0 ? <div className="p-8 text-center sm:p-12"><History aria-hidden="true" className="mx-auto h-8 w-8 text-muted-foreground" /><h2 className="mt-4 text-lg font-semibold">No audit events yet</h2><p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">Repository setup, device access, and encrypted-update metadata will appear here. Secret values never do.</p></div> : <InfiniteScroll dataLength={events.length} next={() => { void loadMore(); }} hasMore={canLoadMore} loader={<p className="px-5 py-4 text-center text-sm text-muted-foreground">Loading older events…</p>} endMessage={<p className="px-5 py-4 text-center text-sm text-muted-foreground">You’ve reached the start of the audit trail.</p>} scrollThreshold="200px"><div className="overflow-x-auto"><table className="w-full min-w-[52rem] text-left text-sm"><thead className="bg-muted text-xs uppercase tracking-wide text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Time</th><th className="px-5 py-3 font-medium">Event</th><th className="px-5 py-3 font-medium">Actor device</th><th className="px-5 py-3 font-medium">Metadata</th></tr></thead><tbody className="divide-y divide-border">{events.map((event, index) => <tr key={`${event.created_at}:${event.event_type}:${index}`}><td className="whitespace-nowrap px-5 py-4 text-xs text-muted-foreground"><time dateTime={event.created_at} title={timestamp(event.created_at)}>{relativeTimestamp(event.created_at)}</time></td><td className="px-5 py-4 font-mono text-xs font-medium">{event.event_type}</td><td className="px-5 py-4 font-mono text-xs text-muted-foreground">{event.actor_device_id || "System"}</td><td className="px-5 py-4"><Metadata event={event} /></td></tr>)}</tbody></table></div></InfiniteScroll>}
      {loadError && <div className="flex items-center justify-center gap-3 border-t border-border px-5 py-4"><p className="text-sm text-warning">Older events could not be loaded.</p><Button variant="secondary" onClick={() => { setCanLoadMore(Boolean(nextCursor)); void loadMore(); }}>Retry</Button></div>}
    </Card>
  </>;
}

function SettingsPage({ page }: { page: DashboardBootstrap }) {
  const [logoFailed, setLogoFailed] = useState(false);
  const publicURL = page.view.settings?.public_url ?? "";
  return <>
    <PageHeading eyebrow="Self-hosted instance" title="Settings"><Badge variant="success"><ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />No secret editor</Badge></PageHeading>
    <div className="grid gap-4 lg:grid-cols-2"><Card className="p-5"><h2 className="text-base font-semibold">Instance details</h2><dl className="mt-4 space-y-4 text-sm"><div><dt className="text-muted-foreground">Display name</dt><dd className="mt-1 font-medium">{page.display_name}</dd></div><div><dt className="text-muted-foreground">Public URL</dt><dd className="mt-1 break-all font-mono text-xs">{publicURL}</dd></div></dl></Card><Card className="p-5"><h2 className="text-base font-semibold">Branding preview</h2><div className="mt-4 flex items-center gap-3 rounded-lg border border-border bg-muted p-4">{page.logo_url && !logoFailed ? <img className="h-10 w-10 rounded-md object-contain" src={page.logo_url} alt={`${page.display_name} logo`} onError={() => setLogoFailed(true)} /> : <span aria-hidden="true" className="grid h-10 w-10 place-items-center rounded-md bg-foreground text-sm font-bold text-background">{page.display_name.slice(0, 1).toUpperCase()}</span>}<div><p className="font-semibold">{page.display_name}</p><p className="text-xs text-muted-foreground">Configured logo and favicon use validated HTTPS URLs.</p></div></div></Card></div>
    <Card className="mt-4 border-success/30 bg-success/10 p-5"><div className="flex gap-3"><Terminal aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0 text-success" /><div><h2 className="font-semibold">Local development values stay local</h2><p className="mt-1 text-sm text-muted-foreground">This self-hosted instance has no telemetry or phone-home behavior. The dashboard does not accept, display, or store secret plaintext; use the CLI for managed values.</p></div></div></Card>
  </>;
}

function SignedOutPage() {
  return <><PageHeading eyebrow="Dashboard session" title="You’re signed out" /><Card className="max-w-xl p-6"><Github aria-hidden="true" className="h-6 w-6" /><h2 className="mt-4 text-lg font-semibold">Your local.env session has ended</h2><p className="mt-2 text-sm text-muted-foreground">Sign in again with GitHub when you want to return to this dashboard.</p><Button asChild className="mt-5"><a href="/login"><Github aria-hidden="true" className="mr-2 h-4 w-4" />Sign in with GitHub</a></Button></Card></>;
}

function SetupPage({ setup }: { setup: DashboardSetup }) {
  if (setup.state === "configuration_required") return <><PageHeading eyebrow="Instance setup" title="Configure GitHub setup" /><Card className="p-6"><CircleAlert aria-hidden="true" className="h-6 w-6 text-warning" /><h2 className="mt-4 text-lg font-semibold">Bootstrap configuration is required</h2><p className="mt-2 text-sm text-muted-foreground">GitHub setup requires the bootstrap OAuth client and credential-encryption key configured by the instance administrator.</p></Card></>;
  if (setup.state === "sign_in") return <><PageHeading eyebrow="Instance setup" title="Connect GitHub" /><Card className="p-6"><Github aria-hidden="true" className="h-6 w-6" /><h2 className="mt-4 text-lg font-semibold">Choose the organization that owns this instance</h2><p className="mt-2 max-w-xl text-sm text-muted-foreground">Sign in with GitHub to select the organization that will own the local.env GitHub App.</p><Button asChild className="mt-5"><a href={setup.sign_in_url}><Github aria-hidden="true" className="mr-2 h-4 w-4" />Sign in with GitHub</a></Button></Card></>;
  if (setup.state === "organization_selection") return <><PageHeading eyebrow="Instance setup" title="Create your GitHub App" /><Card className="p-6"><p className="text-sm text-muted-foreground">Select the organization that will own this GitHub App. The secure server-side handoff continues on GitHub.</p><form className="mt-5 max-w-md" method="post" action="/setup/github-app"><input type="hidden" name="csrf_token" value={setup.csrf_token ?? ""} /><label className="block text-sm font-medium" htmlFor="organization_id">Organization</label><select className="mt-2 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm" id="organization_id" name="organization_id" required>{setup.organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.login}</option>)}</select><Button className="mt-4" type="submit"><Github aria-hidden="true" className="mr-2 h-4 w-4" />Create GitHub App</Button></form></Card></>;
  if (setup.state === "manifest_post") return <><PageHeading eyebrow="Instance setup" title="Create your GitHub App" /><Card className="p-6"><Github aria-hidden="true" className="h-6 w-6" /><h2 className="mt-4 text-lg font-semibold">Continue to GitHub</h2><p className="mt-2 text-sm text-muted-foreground">GitHub will review and create the organization-owned App. This form posts the server-generated manifest directly to GitHub.</p><form className="mt-5" method="post" action={setup.manifest_action}><input type="hidden" name="manifest" value={setup.manifest ?? ""} /><Button type="submit"><ExternalLink aria-hidden="true" className="mr-2 h-4 w-4" />Continue to GitHub</Button></form></Card></>;
  return <><PageHeading eyebrow="Instance setup" title="GitHub App is ready"><Badge variant="success"><CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5" />Setup complete</Badge></PageHeading><Card className="p-6"><CheckCircle2 aria-hidden="true" className="h-6 w-6 text-success" /><h2 className="mt-4 text-lg font-semibold">Install the GitHub App</h2><p className="mt-2 max-w-xl text-sm text-muted-foreground">Install the App in repositories you want local.env to discover. Only repository metadata is shown in this dashboard.</p>{setup.app_url && <Button asChild className="mt-5"><a href={setup.app_url}><Link2 aria-hidden="true" className="mr-2 h-4 w-4" />Install GitHub App</a></Button>}</Card><section className="mt-8"><h2 className="mb-3 flex items-center gap-2 text-base font-semibold"><MonitorCog aria-hidden="true" className="h-4 w-4 text-muted-foreground" />Discovered repositories</h2><Card className="p-5">{setup.repositories.length === 0 ? <p className="text-sm text-muted-foreground">No repositories discovered yet.</p> : <ul className="grid gap-2 text-sm">{setup.repositories.map((repository) => <li key={`${repository.owner}/${repository.name}`} className="font-mono">{repository.owner}/{repository.name}</li>)}</ul>}</Card></section></>;
}

export function OperationalViews({ page }: { page: DashboardBootstrap }) {
  if (page.view.kind === "signed_out") return <SignedOutPage />;
  if (page.view.kind === "devices") return <DevicesPage devices={page.view.devices} />;
  if (page.view.kind === "audit") return <AuditPage initialEvents={page.view.audit_events} initialNextCursor={page.view.audit_next_cursor} />;
  if (page.view.kind === "settings") return <SettingsPage page={page} />;
  if (page.view.kind === "setup" && page.view.setup) return <SetupPage setup={page.view.setup} />;
  return null;
}
