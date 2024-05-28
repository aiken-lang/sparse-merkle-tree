import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  splitting: false,
  sourcemap: true,
  dts: true,
  minify: false,
  clean: true,
  format: ["cjs", "esm"],
});
