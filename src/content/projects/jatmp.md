---
title: "Just Another Threat Monitoring Platform"
short: "JATMP"
description: "A self-hosted platform for monitoring cyber threats and online fraud as they emerge: malware and ransomware campaigns, threat actors, vulnerabilities, indicators of compromise, attacks on critical infrastructure sectors, and the scams aimed at the public. Two dashboards, one for cyber threats and one for scams and fraud, with an International and a National (Indonesia) view."
repo: "https://github.com/fj4rr/just-another-threat-monitoring-platform"
stack: ["Python 3.11+", "FastAPI", "SQLAlchemy", "SQLite / PostgreSQL", "Jinja2", "APScheduler", "Docker"]
status: "Active · v0.10.1"
version: "0.10.1"
license: "MIT (pyproject.toml)"
featured: true
order: 1
tags: ["Threat Intelligence", "Security Tools", "Network Analysis"]
cover: "/images/projects/jatmp/dashboard-overview.png"
coverAlt: "JATMP cyber threats dashboard"
highlights:
  - "Collects from 14 English and 25 Indonesian news feeds, about 30 Bluesky and Mastodon accounts, X, public Telegram channels, OTX, urlscan.io, ANY.RUN, ThreatFox, MISP and ransomware.live"
  - "Two dashboards: Cyber threats and Scams & fraud, with periods from 7 days to a year"
  - "Explainable 0–100 severity score, cross-provider verdicts, relationship graph and CVE context from CISA KEV, EPSS and NVD"
  - "Items tagged with Indonesia's critical infrastructure sectors (Perpres 82/2022)"
  - "Scam tracking: scam types, impersonated banks and e-wallets, scammer identifiers and losses in rupiah"
  - "REST API, IOC blocklist feeds, STIX 2.1 / TAXII 2.1, signed webhooks and two-way MISP"
  - "Outbound guard, encrypted secrets and pinned, audited dependencies (0.10.1)"
  - "Single process with SQLite, no JavaScript build step and nothing loaded from a CDN"
screenshots:
  - { src: "/images/projects/jatmp/dashboard-overview.png", caption: "Cyber threats dashboard" }
  - { src: "/images/projects/jatmp/dashboard.png", caption: "Dashboard: period switch, International / National (ID) switch, threat radar with families, CVEs and actors, globe of the top 10 target countries and KPI tiles" }
  - { src: "/images/projects/jatmp/dashboard-widgets.png", caption: "Trending malware, CVEs (CISA KEV, CVSS, EPSS, risk-weighted priority) and threat actors over the chosen period" }
  - { src: "/images/projects/jatmp/dashboard-sectors.png", caption: "Top 5 trending over time next to the critical infrastructure sectors of the period" }
  - { src: "/images/projects/jatmp/fraud.png", caption: "Scams & fraud dashboard: reports over time by scam type, most targeted countries, trending scam types, impersonated brands and the latest identifiers" }
  - { src: "/images/projects/jatmp/fraud-items.png", caption: "Scam reports ranked by fraud score, with losses in rupiah, scam types and brands" }
  - { src: "/images/projects/jatmp/feed-preview.png", caption: "Feed with the side preview: severity breakdown, entities and indicators without leaving the list" }
  - { src: "/images/projects/jatmp/item.png", caption: "Item page: severity, STIX export, extracted entities with their verdicts" }
  - { src: "/images/projects/jatmp/graph.png", caption: "Relationship graph: the item, its entities and the other items that share them" }
  - { src: "/images/projects/jatmp/geography.png", caption: "Geography: target countries on a world map, with the families and actors named per country" }
  - { src: "/images/projects/jatmp/dashboard-national.png", caption: "National (ID) view: the dashboard limited to Indonesia, with the globe on the provinces" }
  - { src: "/images/projects/jatmp/entity.png", caption: "Malware family page: timeline, coverage per source, deep dive, graph, co-mentioned entities" }
  - { src: "/images/projects/jatmp/iocs.png", caption: "IOC table with verdicts, hosting countries, attributed families and where each indicator was seen" }
  - { src: "/images/projects/jatmp/malware.png", caption: "Malware families: unified table with trend score, related entities and pagination" }
  - { src: "/images/projects/jatmp/cves.png", caption: "CVE list sorted by EPSS, with KEV badges and co-mentioned families" }
  - { src: "/images/projects/jatmp/backfill.png", caption: "Historical backfill: per-source reach and method, estimates and storage statistics" }
  - { src: "/images/projects/jatmp/settings.png", caption: "AI settings: local or cloud, vendor presets and a live model list" }
  - { src: "/images/projects/jatmp/reports.png", caption: "Report builder: period, content and format for the Threat Intel Findings document" }
---

## Overview

JATMP is a self-hosted platform for monitoring cyber threats and online fraud as they emerge. It follows **malware and ransomware campaigns**, **threat actors**, **vulnerabilities** and their exploitation, **indicators of compromise**, attacks on **critical infrastructure sectors**, and the **scams** aimed at the public: investment and loan fraud, phishing and malicious APKs, and impersonated banks, e-wallets and government bodies.

It collects **security news**, **social media** (X, Bluesky, Mastodon, Telegram), **threat-intelligence platforms** and **scam and fraud sources**, extracts the threats, actors, CVEs, indicators, scam types and impersonated brands in each item, checks the indicators against intel providers and correlates everything on one entity graph across sources. So a scam report links to the malware it installs, and a ransomware campaign to the CVEs it exploits. Two dashboards show the result, one for cyber threats and one for scams and fraud. Every item is tagged with the sectors it concerns and placed on the map, and the whole interface switches between an International and a National (Indonesia) view.

It runs as a single process with SQLite by default. There is no JavaScript build step and nothing is loaded from a CDN at runtime, so it works on an isolated network.

## Features

- **Collection** from 14 English news feeds and 25 Indonesian ones (tech and general news), about 30 Bluesky and Mastodon accounts, X, public Telegram channels (no account needed), OTX, urlscan.io, ANY.RUN, ThreatFox, MISP and ransomware.live. Any RSS feed, account or channel can be added.
- **Analysis**: entity extraction with defang handling, an explainable 0–100 severity score, cross-provider verdict consensus (VirusTotal, OTX, abuse.ch, GreyNoise, AbuseIPDB and more), a relationship graph, on-demand infrastructure context, trend scoring over 7 days to a year, critical infrastructure sectors and CVE context from CISA KEV, FIRST EPSS and NVD.
- **Geography**: target, source and hosting countries kept apart, Indonesian provinces, an International / National (ID) switch and Bahasa Indonesia support.
- **Scams and fraud**: scam types, impersonated banks, e-wallets and government bodies, scammer phone numbers, accounts and wallets (kept to a minimum under UU PDP), losses in rupiah and a separate fraud score, from news, fact-checkers, FBI IC3 and the ScamSniffer blocklist, on their own dashboard.
- **Sharing**: REST API with API keys, IOC blocklist feeds, STIX 2.1 / TAXII 2.1, signed webhooks (Slack, Discord, Teams) and two-way MISP, all behind TLP sharing rules.
- **Reporting and AI**: a *Threat Intel Findings* report as PDF, Word, Markdown or CSV, and optional summaries, briefs, a daily executive summary and Q&A from a local or cloud LLM.
- **History**: backfill up to a year back, retention tiers, full-text search and optional PostgreSQL.
- **Operation**: single-user or multi-user with roles, live job progress, a notification center, a side preview on every table, dark and light themes and a phone layout.

## Latest release: 0.10.1

Fixes from a security, data-processing and efficiency audit:

- **Security**: an outbound guard on every request JATMP makes on its own (public addresses only unless allow-listed, checked on every redirect, no DNS rebinding, response bodies capped), API keys and the AI key stored encrypted, a one-time token for first-run setup from another machine, scammer identifiers never returned by the REST API, CSV exports that cannot run as spreadsheet formulas, bounded AI output, per-user rate limits on enrichment and AI, and pinned dependencies checked with `pip-audit`.
- **Data processing**: stricter rules for scammer identifiers, scam phrases, sectors and family names that are everyday words; syndicated copies of a story are counted once in trends and the executive summary; amounts such as "Rp 2,5 T" are read as trillions of rupiah.
- **Efficiency**: new database indexes, one query per page for item entities, cached trending lists, AI summaries in their own job, and a full-text index on PostgreSQL.

A developer guide (development, architecture, data model, extending JATMP) was added to the documentation. Since the release, the AI prompts cover cyber threats and online fraud rather than only malware, and dependencies are kept current by Dependabot.

## Release 0.10.0

- **Two dashboards**: *Cyber threats* and a new *Scams & fraud* dashboard with scam reports over time, a globe of the most targeted countries or provinces, KPI tiles, trending scam types, impersonated brands and the latest scammer identifiers.
- **Dashboard period**: 7 or 15 days, 30 days, 3 or 6 months, or 1 year. Every tile, chart, the radar and the globe follow it.
- **Critical infrastructure sectors**: every item is tagged with the sectors of Indonesia's Perpres 82/2022 it is about (government, energy, transportation, finance, health, ICT, food, defence).
- **Executive summary** instead of the long AI digest: a headline, an overall threat level, key points and up to three actions for today.
- Faster scam and blocklist processing, and a cleaner Backfill page.

Earlier releases also added the Telegram collector and the scam & fraud section (0.9.0), more Indonesian general news sources (0.9.1) and a reworked dashboard with the threat radar and globe (0.8.2). See the [changelog](https://github.com/fj4rr/just-another-threat-monitoring-platform/blob/main/CHANGELOG.md) for details.

## Running it

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python install.py              # interactive: single / multi user, API keys, LLM
python run.py                  # open http://127.0.0.1:8000
```

Or with Docker: copy `.env.example` to `.env` and run `docker compose up -d --build`.

The full documentation, including the new developer guide ([architecture](https://fj4rr.github.io/just-another-threat-monitoring-platform/architecture/), [data model](https://fj4rr.github.io/just-another-threat-monitoring-platform/data-model/), [extending JATMP](https://fj4rr.github.io/just-another-threat-monitoring-platform/extending/)), is on the [JATMP docs site](https://fj4rr.github.io/just-another-threat-monitoring-platform/).
