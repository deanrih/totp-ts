import { $ } from "bun";
import { build, type Options } from "tsup";

const config = {
	bundle: true,
	clean: true,
	dts: true,
	entry: ["./src/**/*.ts"],
	minify: true,
	outDir: "./dist",
	sourcemap: false,
	splitting: false,
	target: "node23",
	treeshake: "smallest",
} satisfies Options;

await $`rm -rf ./dist`;

await Promise.all([
	build({
		...config,
		format: "cjs",
	}),
	build({
		...config,
		format: "esm",
		outExtension: () => {
			return { js: ".mjs" };
		},
	}),
]);


// import { defineConfig } from 'npm:tsup@^8.1.0';

// export default defineConfig([
//   {
//     entry: ['./src/index.ts'],
//     clean: true,
//     format: ['esm', 'cjs'],
//     minify: false,
//     dts: true,
//     outDir: './dist',
//   },
//   {
//     entry: ['./src/index.ts'],
//     clean: true,
//     format: ['esm', 'cjs'],
//     minify: true,
//     dts: false,
//     outDir: './dist',
//     outExtension: ({ format }) => ({
//       js: format === 'cjs' ? '.min.cjs' : '.min.js',
//     }),
//   },
// ]);