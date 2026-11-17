// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { unified } from '@astrojs/markdown-remark';
import remarkCallouts from './src/plugins/remark-callouts.mjs';
import rehypeEnhance from './src/plugins/rehype-enhance.mjs';
import terminalTheme from './src/plugins/shiki-theme.mjs';

// https://fj4rr.github.io is a GitHub *user* site, so it is served from the root ("base" stays "/").
export default defineConfig({
  site: 'https://fj4rr.github.io',
  trailingSlash: 'always',
  integrations: [sitemap()],
  prefetch: { prefetchAll: true, defaultStrategy: 'hover' },
  markdown: {
    syntaxHighlight: { type: 'shiki', excludeLangs: ['mermaid'] },
    shikiConfig: { theme: terminalTheme, wrap: false },
    // remark/rehype pipeline (kept so GitHub-style reports render unchanged)
    processor: unified({ remarkPlugins: [remarkCallouts], rehypePlugins: [rehypeEnhance] }),
  },
});
