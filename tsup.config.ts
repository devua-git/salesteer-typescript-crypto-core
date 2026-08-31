import { defineConfig } from 'tsup'

export default defineConfig({
  clean: true,
  dts: {
    compilerOptions: {
      ignoreDeprecations: '6.0',
    },
  },
  entry: ['src/index.ts'],
  format: ['esm'],
  platform: 'browser',
  sourcemap: true,
  splitting: false,
  target: 'es2022',
  treeshake: true,
})
