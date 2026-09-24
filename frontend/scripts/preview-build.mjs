// Offline, credential-free visual preview. Never use this file as a deployment.
import { build } from 'vite';
import { readFile, writeFile } from 'node:fs/promises';
const output = process.argv[2];
if (!output) throw new Error('Provide an absolute scratch output directory.');
await build({ define: { 'import.meta.env.VITE_SUPABASE_URL': '""', 'import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY': '""' }, build: { outDir: output, emptyOutDir: true, cssCodeSplit: false, rollupOptions: { output: { format: 'iife', inlineDynamicImports: true, entryFileNames: 'app.js', assetFileNames: '[name][extname]' } } } });
const js = await readFile(output + '/app.js', 'utf8');
const css = await readFile(output + '/style.css', 'utf8');
await writeFile(output + '/preview.html', '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>EVIDENCE — offline visual preview</title><style>' + css + '</style><body><div id="root"></div><script>' + js.replaceAll('</script', '<\\/script') + '</script></body></html>');
