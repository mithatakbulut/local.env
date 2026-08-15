import { createRoot } from "react-dom/client";

import { DashboardShell, readDashboardBootstrap } from "@/components/dashboard-shell";
import { OperationalViews } from "@/components/operational-views";
import { RepositoryViews } from "@/components/repository-views";
import "./index.css";

const root = document.getElementById("dashboard-shell");
const page = root && readDashboardBootstrap(root);
if (root && page) createRoot(root).render(<DashboardShell page={page} />);

const content = document.getElementById("dashboard-page");
if (content && page) createRoot(content).render(<><RepositoryViews page={page} /><OperationalViews page={page} /></>);
