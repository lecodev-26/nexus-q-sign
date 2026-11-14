import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  // Tauri serves bundled assets through its app protocol, not from the site root.
  // Relative URLs keep JS, CSS and static assets resolvable in packaged builds.
  base: "./",
  plugins: [svelte()],
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**", "**/target/**"] },
  },
  build: {
    target: "es2022",
    sourcemap: false,
  },
});
