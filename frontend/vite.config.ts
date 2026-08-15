import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": resolve(import.meta.dirname, ".") },
  },
  build: {
    outDir: resolve(import.meta.dirname, "../internal/server/ui/dist"),
    emptyOutDir: true,
    assetsDir: "assets",
    sourcemap: false,
    manifest: false,
  },
});
