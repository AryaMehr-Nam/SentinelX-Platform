import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: `http://localhost:${process.env.VITE_BACKEND_PORT || "8000"}`,
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/recharts")) {
            return "vendor-recharts";
          }
          if (id.includes("node_modules/lucide-react")) {
            return "vendor-icons";
          }
          if (id.includes("node_modules/react") || id.includes("node_modules/react-dom") || id.includes("node_modules/react-router-dom")) {
            return "vendor-react";
          }
          if (id.includes("node_modules/@tanstack") || id.includes("node_modules/axios") || id.includes("node_modules/zustand")) {
            return "vendor-state";
          }
        },
      },
    },
  },
  // @ts-expect-error vitest config
  test: {
    environment: "jsdom",
    globals: true,
  },
});
