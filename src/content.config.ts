import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

export const BLOG_CATEGORIES = [
  'Malware Analysis',
  'Threat Intelligence',
  'Reverse Engineering',
  'Security Research',
  'Technical Tutorials',
] as const;

const blog = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/blog' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    updated: z.coerce.date().optional(),
    category: z.enum(BLOG_CATEGORIES),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
    featured: z.boolean().default(false),
    /** How the analysis was done, shown as a badge on cards and the article header (e.g. "AI-assisted malware analysis"). */
    method: z.string().optional(),
    /** Original source of the write-up (e.g. the GitHub folder it was migrated from). */
    source: z.string().url().optional(),
    /** Downloadable companion files (YARA rules, IOC lists ...). Paths are relative to /public. */
    attachments: z.array(z.object({ label: z.string(), href: z.string(), note: z.string().optional() })).default([]),
    /** Cover image in /public. When absent, a banner is drawn from `chain`. */
    cover: z.string().optional(),
    coverAlt: z.string().optional(),
    /** Illustration shown beside the title in the article header (image in /public). */
    art: z.string().optional(),
    artAlt: z.string().optional(),
    /** Stages of the infection chain, used to draw the article banner and the card thumbnail. */
    chain: z.array(z.string()).default([]),
    /** Short facts shown under the article header. */
    facts: z.array(z.object({ label: z.string(), value: z.string() })).default([]),
  }),
});

const projects = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/projects' }),
  schema: z.object({
    title: z.string(),
    short: z.string().optional(),
    description: z.string(),
    repo: z.string().url(),
    stack: z.array(z.string()).default([]),
    /** Only set what can be verified from the repository. */
    status: z.string().optional(),
    version: z.string().optional(),
    license: z.string().optional(),
    featured: z.boolean().default(false),
    order: z.number().default(100),
    tags: z.array(z.string()).default([]),
    cover: z.string().optional(),
    coverAlt: z.string().optional(),
    screenshots: z.array(z.object({ src: z.string(), caption: z.string() })).default([]),
    highlights: z.array(z.string()).default([]),
  }),
});

export const collections = { blog, projects };
