import { useEffect, useState } from "react";
import { Activity, BookOpen, ChevronRight, Laptop, Menu, Settings, ShieldCheck, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export type DashboardRepository = {
  owner: string;
  name: string;
  default_branch: string;
  active_key_epoch: number;
  revision: number;
  managed_key_count: number;
  open_pull_request_count: number;
  missing_requirement_count: number;
  files: { schema_path: string; target_path: string }[];
  open_pull_requests: DashboardPullRequest[];
};

export type DashboardPullRequest = {
  number: number;
  state: string;
  missing_requirement_count: number;
  requirements: { key_name: string; state: string }[];
};

export type DashboardDevice = {
  id: string;
  github_login: string;
  name: string;
  fingerprint: string;
  created_at: string;
  last_seen_at: string;
  revoked_at?: string;
  has_key: boolean;
};

export type DashboardAuditEvent = {
  event_type: string;
  actor_device_id: string;
  metadata: { key: string; value: string }[];
  created_at: string;
};

export type DashboardAuditPage = {
  events: DashboardAuditEvent[];
  next_cursor?: string;
};

export type DashboardSetup = {
  state: "configuration_required" | "complete" | "sign_in" | "organization_selection" | "manifest_post";
  sign_in_url?: string;
  csrf_token?: string;
  organizations: { id: number; login: string }[];
  app_url?: string;
  repositories: { owner: string; name: string }[];
  manifest_action?: string;
  manifest?: string;
};

type DashboardView = {
  kind: "legacy" | "repositories" | "repository" | "pull_request" | "devices" | "audit" | "settings" | "setup";
  repositories: DashboardRepository[];
  repository?: DashboardRepository;
  pull_request?: DashboardPullRequest;
  devices: DashboardDevice[];
  audit_events: DashboardAuditEvent[];
  audit_next_cursor?: string;
  settings?: { public_url: string };
  setup?: DashboardSetup;
  owner: string;
  repo: string;
};

export type DashboardBootstrap = {
  display_name: string;
  logo_url?: string;
  path: string;
  title: string;
  user: string;
  view: DashboardView;
};

const navigation = [
  { href: "/repos", label: "Repositories", icon: BookOpen },
  { href: "/devices", label: "Devices", icon: Laptop },
  { href: "/audit", label: "Audit", icon: Activity },
  { href: "/settings", label: "Settings", icon: Settings },
];

function isBootstrap(value: unknown): value is DashboardBootstrap {
  if (!value || typeof value !== "object") return false;
  const page = value as Partial<DashboardBootstrap>;
  return typeof page.display_name === "string" && typeof page.path === "string" && typeof page.title === "string" && typeof page.user === "string" && isView(page.view);
}

function isRequirement(value: unknown): value is DashboardPullRequest["requirements"][number] {
  if (!value || typeof value !== "object") return false;
  const requirement = value as { key_name?: unknown; state?: unknown };
  return typeof requirement.key_name === "string" && typeof requirement.state === "string";
}

function isPullRequest(value: unknown): value is DashboardPullRequest {
  if (!value || typeof value !== "object") return false;
  const pull = value as Partial<DashboardPullRequest>;
  return typeof pull.number === "number" && typeof pull.state === "string" && typeof pull.missing_requirement_count === "number" && Array.isArray(pull.requirements) && pull.requirements.every(isRequirement);
}

function isRepository(value: unknown): value is DashboardRepository {
  if (!value || typeof value !== "object") return false;
  const repository = value as Partial<DashboardRepository>;
  return typeof repository.owner === "string" && typeof repository.name === "string" && typeof repository.default_branch === "string" && typeof repository.active_key_epoch === "number" && typeof repository.revision === "number" && typeof repository.managed_key_count === "number" && typeof repository.open_pull_request_count === "number" && typeof repository.missing_requirement_count === "number" && Array.isArray(repository.files) && repository.files.every((file) => Boolean(file) && typeof file === "object" && typeof (file as { schema_path?: unknown }).schema_path === "string" && typeof (file as { target_path?: unknown }).target_path === "string") && Array.isArray(repository.open_pull_requests) && repository.open_pull_requests.every(isPullRequest);
}

function isDevice(value: unknown): value is DashboardDevice {
  if (!value || typeof value !== "object") return false;
  const device = value as Partial<DashboardDevice>;
  return typeof device.id === "string" && typeof device.github_login === "string" && typeof device.name === "string" && typeof device.fingerprint === "string" && typeof device.created_at === "string" && typeof device.last_seen_at === "string" && (device.revoked_at === undefined || typeof device.revoked_at === "string") && typeof device.has_key === "boolean";
}

function isAuditEvent(value: unknown): value is DashboardAuditEvent {
  if (!value || typeof value !== "object") return false;
  const event = value as Partial<DashboardAuditEvent>;
  return typeof event.event_type === "string" && typeof event.actor_device_id === "string" && typeof event.created_at === "string" && Array.isArray(event.metadata) && event.metadata.every((metadata) => Boolean(metadata) && typeof metadata === "object" && typeof (metadata as { key?: unknown }).key === "string" && typeof (metadata as { value?: unknown }).value === "string");
}

function isSetup(value: unknown): value is DashboardSetup {
  if (!value || typeof value !== "object") return false;
  const setup = value as Partial<DashboardSetup>;
  return (setup.state === "configuration_required" || setup.state === "complete" || setup.state === "sign_in" || setup.state === "organization_selection" || setup.state === "manifest_post") && (setup.sign_in_url === undefined || typeof setup.sign_in_url === "string") && (setup.csrf_token === undefined || typeof setup.csrf_token === "string") && (setup.app_url === undefined || typeof setup.app_url === "string") && (setup.manifest_action === undefined || typeof setup.manifest_action === "string") && (setup.manifest === undefined || typeof setup.manifest === "string") && Array.isArray(setup.organizations) && setup.organizations.every((organization) => Boolean(organization) && typeof organization === "object" && typeof (organization as { id?: unknown }).id === "number" && typeof (organization as { login?: unknown }).login === "string") && Array.isArray(setup.repositories) && setup.repositories.every((repository) => Boolean(repository) && typeof repository === "object" && typeof (repository as { owner?: unknown }).owner === "string" && typeof (repository as { name?: unknown }).name === "string");
}

function isView(value: unknown): value is DashboardView {
  if (!value || typeof value !== "object") return false;
  const view = value as Partial<DashboardView>;
  if (view.kind === "legacy") return true;
  if (view.kind === "repositories") return Array.isArray(view.repositories) && view.repositories.every(isRepository);
  if (view.kind === "repository") return isRepository(view.repository);
  if (view.kind === "pull_request") return isPullRequest(view.pull_request) && typeof view.owner === "string" && typeof view.repo === "string";
  if (view.kind === "devices") return Array.isArray(view.devices) && view.devices.every(isDevice);
  if (view.kind === "audit") return Array.isArray(view.audit_events) && view.audit_events.every(isAuditEvent) && (view.audit_next_cursor === undefined || typeof view.audit_next_cursor === "string");
  if (view.kind === "settings") return Boolean(view.settings) && typeof view.settings?.public_url === "string";
  return view.kind === "setup" && isSetup(view.setup);
}

function BrandMark({ page }: { page: DashboardBootstrap }) {
  const [logoFailed, setLogoFailed] = useState(false);
  const showLogo = page.logo_url && !logoFailed;
  return (
    <a className="flex min-w-0 items-center gap-3 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-success" href={page.path === "/setup" ? "/setup" : "/repos"}>
      {showLogo ? (
        <img className="h-8 w-8 rounded-md object-contain" src={page.logo_url} alt={`${page.display_name} logo`} onError={() => setLogoFailed(true)} />
      ) : (
        <span aria-hidden="true" className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-foreground text-sm font-bold text-background">{page.display_name.slice(0, 1).toUpperCase()}</span>
      )}
      <span className="truncate text-sm font-semibold tracking-tight">{page.display_name}</span>
    </a>
  );
}

function Navigation({ page, onNavigate }: { page: DashboardBootstrap; onNavigate?: () => void }) {
  if (page.path === "/setup") return null;
  return (
    <nav aria-label="Primary navigation" className="space-y-1">
      {navigation.map(({ href, label, icon: Icon }) => {
        const active = page.path === href || (href === "/repos" && page.path.startsWith("/repos/"));
        return (
          <a key={href} href={href} onClick={onNavigate} aria-current={active ? "page" : undefined} className={cn("flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors", active ? "bg-foreground text-background" : "text-muted-foreground hover:bg-muted hover:text-foreground")}>
            <Icon aria-hidden="true" className="h-4 w-4" />
            {label}
            {active && <ChevronRight aria-hidden="true" className="ml-auto h-4 w-4" />}
          </a>
        );
      })}
    </nav>
  );
}

export function DashboardShell({ page }: { page: DashboardBootstrap }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    document.body.classList.add("dashboard-ui");
    return () => document.body.classList.remove("dashboard-ui");
  }, []);

  const isSetup = page.path === "/setup";
  return (
    <>
      <aside className={cn("fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-border bg-background p-4 md:flex md:flex-col", isSetup && "hidden")}>
        <BrandMark page={page} />
        <div className="mt-8"><Navigation page={page} /></div>
        <div className="mt-auto border-t border-border pt-4">
          <Badge><ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />Metadata only</Badge>
          <p className="mt-3 truncate text-xs text-muted-foreground">Signed in as {page.user}</p>
        </div>
      </aside>

      <header className={cn("fixed inset-x-0 top-0 z-20 flex h-16 items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur md:left-64", isSetup && "md:left-0")}>
        <div className="md:hidden"><BrandMark page={page} /></div>
        <div className="hidden md:block">
          <p className="text-xs font-medium text-muted-foreground">{isSetup ? "Instance setup" : "Operational dashboard"}</p>
          <p className="text-sm font-semibold">{page.title}</p>
        </div>
        {!isSetup && <button type="button" className="rounded-md border border-border p-2 text-foreground md:hidden" aria-expanded={open} aria-controls="mobile-navigation" aria-label={open ? "Close navigation" : "Open navigation"} onClick={() => setOpen((value) => !value)}>{open ? <X aria-hidden="true" className="h-5 w-5" /> : <Menu aria-hidden="true" className="h-5 w-5" />}</button>}
        {isSetup && <Badge variant="success"><ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />Self-hosted</Badge>}
      </header>

      {open && !isSetup && <div id="mobile-navigation" className="fixed inset-x-0 top-16 z-10 border-b border-border bg-background p-4 shadow-sm md:hidden"><Navigation page={page} onNavigate={() => setOpen(false)} /></div>}
    </>
  );
}

export function readDashboardBootstrap(root: HTMLElement): DashboardBootstrap | null {
  try {
    const parsed: unknown = JSON.parse(root.dataset.dashboard ?? "");
    return isBootstrap(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
