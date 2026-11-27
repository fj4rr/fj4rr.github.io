---
title: "Just Another Threat Monitoring Platform"
short: "JATMP"
description: "A self-hosted platform for monitoring cyber threats and online fraud as they emerge: malware and ransomware campaigns, threat actors, vulnerabilities, indicators of compromise, attacks on critical infrastructure sectors, and the scams aimed at the public. Two dashboards, one for cyber threats and one for scams and fraud, with an International and a National (Indonesia) view."
repo: "https://github.com/fj4rr/just-another-threat-monitoring-platform"
docs: "https://fj4rr.github.io/just-another-threat-monitoring-platform/"
stack: ["Python 3.11+", "FastAPI", "SQLAlchemy", "SQLite / PostgreSQL", "Jinja2", "APScheduler", "Docker"]
status: "Active · v1.0.0"
version: "1.0.0"
license: "MIT"
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
  - "Scam tracking with its own feed: scam types, impersonated banks, e-wallets and public figures, scammer identifiers and losses in rupiah"
  - "REST API, IOC blocklist feeds, STIX 2.1 / TAXII 2.1, signed webhooks and two-way MISP"
  - "First public release: MIT licence, security policy, contribution guidelines and semantic versioning from here on"
  - "Analyst corrections with an audit trail, and rule quality measured with precision and recall on labelled cases"
  - "One counting rule: a story carried by several outlets counts once in every figure; verdicts that age and are re-checked"
  - "Outbound guard, encrypted secrets and pinned, audited dependencies"
  - "Single process with SQLite, no JavaScript build step and nothing loaded from a CDN"
screenshots:
  - { src: "/images/projects/jatmp/dashboard-overview.png", caption: "Cyber threats dashboard" }
  - { src: "/images/projects/jatmp/dashboard.png", caption: "Dashboard: the collapsible, grouped menu, period switch, International / National (ID) switch, threat radar with families, CVEs and actors, globe of the top 10 target countries and KPI tiles" }
  - { src: "/images/projects/jatmp/dashboard-widgets.png", caption: "Trending malware, CVEs (CISA KEV, CVSS, EPSS, risk-weighted priority) and threat actors over the chosen period" }
  - { src: "/images/projects/jatmp/dashboard-sectors.png", caption: "Top 5 trending over time next to the critical infrastructure sectors of the period" }
  - { src: "/images/projects/jatmp/fraud.png", caption: "Scams & fraud dashboard: reports over time by scam type, most targeted countries, trending scam types, impersonated brands and the latest identifiers" }
  - { src: "/images/projects/jatmp/fraud-items.png", caption: "Scams & fraud feed: scam reports ranked by fraud score, with losses in rupiah, scam types and brands" }
  - { src: "/images/projects/jatmp/feed-preview.png", caption: "Feed with the side preview: severity breakdown, entities and indicators without leaving the list" }
  - { src: "/images/projects/jatmp/item.png", caption: "Item page: severity, STIX export, extracted entities with their verdicts" }
  - { src: "/images/projects/jatmp/graph.png", caption: "Relationship graph: the item, its entities and the other items that share them" }
  - { src: "/images/projects/jatmp/geography.png", caption: "Geography: target countries on a world map, with the families and actors named per country" }
  - { src: "/images/projects/jatmp/dashboard-national.png", caption: "National (ID) view: the dashboard limited to Indonesia, with the globe on the provinces" }
  - { src: "/images/projects/jatmp/entity.png", caption: "Malware family page: timeline, coverage per source, deep dive, graph, co-mentioned entities" }
  - { src: "/images/projects/jatmp/iocs.png", caption: "IOC table with verdicts, hosting countries, attributed families and where each indicator was seen" }
  - { src: "/images/projects/jatmp/malware.png", caption: "Malware families: unified table with trend score, related entities and pagination" }
  - { src: "/images/projects/jatmp/cves.png", caption: "CVE list sorted by EPSS, with KEV badges, co-mentioned families and the New threats button" }
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
- **Scams and fraud**: scam types, impersonated banks, e-wallets, government bodies and public figures, scammer phone numbers, accounts and wallets (kept to a minimum under UU PDP), losses in rupiah and a separate fraud score, from news, fact-checkers, FBI IC3 and the ScamSniffer blocklist, on their own dashboard and feed.
- **Sharing**: REST API with API keys, IOC blocklist feeds, STIX 2.1 / TAXII 2.1, signed webhooks (Slack, Discord, Teams) and two-way MISP, all behind TLP sharing rules.
- **Reporting and AI**: a *Threat Intel Findings* report as PDF, Word, Markdown or CSV, and optional summaries, briefs, a daily executive summary and Q&A from a local or cloud LLM.
- **History**: backfill up to a year back, retention tiers, full-text search and optional PostgreSQL.
- **Operation**: single-user or multi-user with roles, live job progress, a notification center, a side preview on every table, dark and light themes and a phone layout.

## Latest release: 1.0.0

The **first public release**. JATMP is now released under the MIT License, and from this version on releases follow [semantic versioning](https://semver.org/). Upgrading from 0.14.1 is just a restart: no schema change and no re-analysis.

- **Project**: an MIT `LICENSE` with third-party notices (Chart.js, Natural Earth, DB-IP / MaxMind GeoLite2, provider terms), a `SECURITY.md` with supported versions, private reporting through GitHub's *Report a vulnerability* form, response times and scope, plus `CONTRIBUTING.md`, a code of conduct, issue forms (bug, wrong or missed detection, feature or source) and a pull request checklist. The version now lives in one place.
- **A busy AI model no longer costs the executive summary**: the scheduled run is queued again 20 and then 60 minutes later, and *Summarise*, *Write brief*, *AI summary* and *Ask* answer 503 with the provider's own message instead of a 400 as if the request were wrong.
- **Docs**: a new [Known limitations](https://fj4rr.github.io/just-another-threat-monitoring-platform/limitations/) page (single process, feed-text-only analysis, rule-based detection and what its quality numbers mean, word-based Q&A, no single sign-on), and a quick start that installs from the lock file.

Upgrade notes are in [Upgrading](https://fj4rr.github.io/just-another-threat-monitoring-platform/upgrading/); earlier releases are in the [changelog](https://fj4rr.github.io/just-another-threat-monitoring-platform/changelog/).

## Running it

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt -c requirements.lock
python install.py              # interactive: single / multi user, API keys, LLM
python run.py                  # open http://127.0.0.1:8000
```

Or with Docker: copy `.env.example` to `.env` and run `docker compose up -d --build`.

The full documentation, including [How it works](https://fj4rr.github.io/just-another-threat-monitoring-platform/how-it-works/) and the developer guide ([architecture](https://fj4rr.github.io/just-another-threat-monitoring-platform/architecture/), [data model](https://fj4rr.github.io/just-another-threat-monitoring-platform/data-model/), [extending JATMP](https://fj4rr.github.io/just-another-threat-monitoring-platform/extending/)), is on the [JATMP docs site](https://fj4rr.github.io/just-another-threat-monitoring-platform/).
