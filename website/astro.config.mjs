import { defineConfig } from "astro/config";
import { unified } from "@astrojs/markdown-remark";
import sitemap from "@astrojs/sitemap";
import starlight from "@astrojs/starlight";
import rehypeMermaid from "rehype-mermaid";

function wrapMermaidDiagrams() {
  const wrap = (node) => {
    if (!node?.children) return;
    for (let index = 0; index < node.children.length; index += 1) {
      const child = node.children[index];
      if (child.type === "element" && child.tagName === "svg" && String(child.properties?.id ?? "").startsWith("mermaid")) {
        node.children[index] = {
          type: "element",
          tagName: "figure",
          properties: { className: ["diagram"] },
          children: [child]
        };
      } else {
        wrap(child);
      }
    }
  };
  return (tree) => wrap(tree);
}

export default defineConfig({
  site: "https://www.local.env.best",
  output: "static",
  build: {
    inlineStylesheets: "never"
  },
  markdown: {
    syntaxHighlight: {
      type: "shiki",
      excludeLangs: ["mermaid"]
    },
    processor: unified({
      rehypePlugins: [
        [rehypeMermaid, {
          colorScheme: "dark",
          mermaidConfig: {
            theme: "dark",
            fontFamily: "Figtree Variable, ui-sans-serif, system-ui, sans-serif",
            flowchart: { htmlLabels: false }
          },
          strategy: "inline-svg"
        }],
        wrapMermaidDiagrams
      ]
    })
  },
  integrations: [
    sitemap(),
    starlight({
      title: "local.env documentation",
      disable404Route: true,
      customCss: ["./src/styles/docs.css"],
      components: {
        ThemeProvider: "./src/components/starlight/ThemeProvider.astro",
        ThemeSelect: "./src/components/starlight/ThemeSelect.astro"
      },
      editLink: {
        baseUrl: "https://github.com/mithatakbulut/local.env/edit/main/website/"
      },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/mithatakbulut/local.env"
        }
      ],
      head: [
        {
          tag: "link",
          attrs: {
            rel: "icon",
            href: "/favicon.png",
            type: "image/png"
          }
        }
      ],
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Documentation home", slug: "docs" },
            { label: "Overview", slug: "docs/overview" }
          ]
        },
        {
          label: "Self-host an instance",
          items: [
            { label: "Prerequisites", slug: "docs/self-host/prerequisites" },
            { label: "Deploy with Docker", slug: "docs/self-host/deploy-with-docker" },
            { label: "Public URL and TLS", slug: "docs/self-host/configure-public-url-and-tls" },
            { label: "GitHub OAuth", slug: "docs/self-host/configure-github-oauth" },
            { label: "Create and install GitHub App", slug: "docs/self-host/create-and-install-github-app" },
            { label: "Instance branding", slug: "docs/self-host/configure-instance-branding" },
            { label: "Verify your instance", slug: "docs/self-host/verify-your-instance" }
          ]
        },
        {
          label: "Join an instance",
          items: [
            { label: "Prerequisites", slug: "docs/join-an-instance/prerequisites" },
            { label: "Install the CLI", slug: "docs/join-an-instance/install-the-cli" },
            { label: "Sign in and register device", slug: "docs/join-an-instance/sign-in-and-register-device" },
            { label: "Initialize a repository", slug: "docs/join-an-instance/initialize-a-repository" },
            { label: "Resolve PR requirements", slug: "docs/join-an-instance/resolve-pr-requirements" },
            { label: "Sync safely", slug: "docs/join-an-instance/sync-safely" },
            { label: "Verify your first sync", slug: "docs/join-an-instance/verify-your-first-sync" }
          ]
        },
        {
          label: "Use local.env",
          items: [
            { label: "Everyday CLI workflows", slug: "docs/use-localenv/everyday-cli-workflows" },
            { label: "Runtime mode", slug: "docs/use-localenv/runtime-mode" },
            { label: "Device approval and revocation", slug: "docs/use-localenv/device-approval-and-revocation" },
            { label: "Key rotation", slug: "docs/use-localenv/key-rotation" }
          ]
        },
        {
          label: "Operate",
          items: [
            { label: "Backup, restore, and upgrades", slug: "docs/operate/backup-restore-and-upgrades" },
            { label: "Troubleshooting", slug: "docs/operate/troubleshooting" }
          ]
        },
        {
          label: "Security",
          items: [
            { label: "Security model", slug: "docs/security/security-model" },
            { label: "Threat model and limitations", slug: "docs/security/threat-model-and-limitations" },
            { label: "Security advisories", slug: "docs/security/security-advisories" }
          ]
        },
        {
          label: "Reference",
          items: [
            { label: "CLI commands", slug: "docs/reference/cli-commands" },
            { label: "Environment variables", slug: "docs/reference/environment-variables" },
            { label: "GitHub App permissions", slug: "docs/reference/github-app-permissions" }
          ]
        }
      ]
    })
  ]
});
