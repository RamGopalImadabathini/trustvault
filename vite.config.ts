import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: (process.env.VITE_ALLOWED_HOSTS ?? "")
      .split(",")
      .map((host) => host.trim())
      .filter(Boolean),
    proxy: {
      "/api": {
        target: process.env.TRUSTVAULT_API_TARGET ?? "http://127.0.0.1:3000",
        changeOrigin: false
      }
    }
  },
  build: {
    outDir: "dist/client",
    emptyOutDir: false
  }
});
