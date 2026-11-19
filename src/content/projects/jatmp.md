---
title: "Just Another Threat Monitoring Platform"
short: "JATMP"
description: "A self-hosted platform for monitoring cyber threats and online fraud as they emerge: malware and ransomware campaigns, threat actors, vulnerabilities, indicators of compromise, attacks on critical infrastructure sectors, and the scams aimed at the public. Two dashboards, one for cyber threats and one for scams and fraud, with an International and a National (Indonesia) view."
repo: "https://github.com/fj4rr/just-another-threat-monitoring-platform"
docs: "https://fj4rr.github.io/just-another-threat-monitoring-platform/"
stack: ["Python 3.11+", "FastAPI", "SQLAlchemy", "SQLite / PostgreSQL", "Jinja2", "APScheduler", "Docker"]
status: "Active · v0.13.1"
version: "0.13.1"
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
  - "Analyst corrections with an audit trail, and rule quality measured with precision and recall on labelled cases (0.13)"
  - "One counting rule: a story carried by several outlets counts once in every figure; verdicts that age and are re-checked (0.12)"
  - "Outbound guard, encrypted secrets and pinned, audited dependencies"
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

## Since 0.13.1 (on main, not yet released)

- **Feed filters stay** when you pick another one, for the whole session, until *Clear filters*; a chip under the filter bar removes a single entity, country or province.
- **Tidier menu**: Cyber threats, Scams & fraud and Feed on top, Intelligence, Analysis and Manage as dropdowns, and the whole menu collapses to an icon rail.
- **New threats** button on the Intelligence lists (malware, threat actors, CVEs, IOCs, scam types and impersonated brands) keeps only what was first seen in the chosen period.
- **Fixes**: the default urlscan.io source now searches `task.tags:malicious`, which free accounts allow (the old query failed with 403), and two enrichment failures are gone (a duplicate entity link and a crash in the final summary).
- Higher minimum versions of `anthropic`, `feedparser`, `python-docx`, `psycopg` and `telethon`.

See [Using JATMP](https://fj4rr.github.io/just-another-threat-monitoring-platform/using-jatmp/) for the new menu, filters and *New threats* button.

## Latest release: 0.13.1

Rule tuning from the first quality report. Every fix comes with the case that motivated it and counter-examples that must not change:

- **Indicators**: "server 91.92.243.10" is no longer read as a version number, public DNS resolvers (`8.8.8.8`, `1.1.1.1`…) are not indicators, and on paste and file-sharing services (Pastebin, GitHub, Google Drive, Dropbox, MEGA…) the URL of the paste or file is the indicator, not the service's domain.
- **Families**: a name that is also an everyday word counts when written in its own distinctive spelling ("RedLine", "Cl0p", "SafePay").
- **Geography, scams, sectors and severity**: marketplaces and hosting are no longer targets; scam phrases such as "mengaku dari Bea Cukai / polisi / bank", fake QRIS stickers, smishing and fake sellers are recognised; fuel stations (SPBU) are energy; severity picks up service disruption, the scale of a leak, data put up for sale and stolen credentials.
- **Quality on the seed set** (172 cases): precision and recall 1.000 for families, indicators, scams, sectors and severity; geography precision 1.000, recall 0.955.

## Release 0.13.0

- **Analyst corrections**: analysts can mark an entity as wrong on one item or everywhere, set an analyst verdict that wins over the providers, and mark an item as not a scam report. Each correction needs a reason, is logged with the analyst's name, can be undone, and stays in force through re-extraction, AI extraction and enrichment. A new *Corrections* page shows the log, the error rate per area and the names corrected most often.
- **Quality measurement**: `python manage.py quality` reports precision, recall and F1 of the extractor, scam rules, sectors, target countries and severity on labelled cases, and CI fails when an area drops below the baseline.
- **Topic filters** (`security`, `cyber`, `fraud`) for every news and social source, including Telegram, X, Mastodon and Bluesky.
- **Better Q&A**: questions find items by the entities, malware types, sectors and periods they name, and answers cite their items as links.

## Releases 0.11.0 and 0.12.0

Two releases from a product review, about trust in the numbers and operations:

- **One counting rule** (0.12): a story carried by several outlets counts once in every figure, from KPI tiles to reports. The feed lists each story once and shows its syndicated copies on request (0.11).
- **Severity you can compare**: a rules version re-scores stored items once when the rules change, and re-scoring keeps enrichment bonuses and AI assessments.
- **Verdicts that age**: indicators show "verdict as of …", malicious IPs, domains and URLs are re-checked after 30 days and leave the export feeds and TAXII after 60 days without confirmation.
- **Source health and enrichment queue**: last new item and usual rate per source, alerts for sources that went quiet or keep failing, lookups used against each provider's daily budget, and every provider queried at its own pace.
- **Personal data out of cloud prompts**: phone and e-wallet numbers, bank accounts, ID numbers and e-mail addresses are replaced with placeholders before a prompt goes to a cloud model.
- **Operations**: a time zone and times for the daily jobs, and a TLP on every new source.

The documentation gained a [How it works](https://fj4rr.github.io/just-another-threat-monitoring-platform/how-it-works/) section that follows one article from the feed to the dashboard and explains every process with the rules and numbers it uses, including [corrections and quality](https://fj4rr.github.io/just-another-threat-monitoring-platform/how-it-works/corrections/).

## Earlier releases

0.10.1 came from a security, data-processing and efficiency audit: an outbound guard on every request JATMP makes on its own, encrypted API keys, a one-time token for remote first-run setup, formula-safe CSV exports, per-user rate limits, pinned dependencies checked with `pip-audit`, and new indexes and caching. 0.10.0 split the interface into the *Cyber threats* and *Scams & fraud* dashboards, added the dashboard period, the critical infrastructure sectors of Perpres 82/2022 and the executive summary. Before that came the Telegram collector and the scam & fraud section (0.9.0), more Indonesian general news sources (0.9.1) and the reworked dashboard with the threat radar and globe (0.8.2). See the [changelog](https://github.com/fj4rr/just-another-threat-monitoring-platform/blob/main/CHANGELOG.md) for details.

## Running it

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python install.py              # interactive: single / multi user, API keys, LLM
python run.py                  # open http://127.0.0.1:8000
```

Or with Docker: copy `.env.example` to `.env` and run `docker compose up -d --build`.

The full documentation, including [How it works](https://fj4rr.github.io/just-another-threat-monitoring-platform/how-it-works/) and the developer guide ([architecture](https://fj4rr.github.io/just-another-threat-monitoring-platform/architecture/), [data model](https://fj4rr.github.io/just-another-threat-monitoring-platform/data-model/), [extending JATMP](https://fj4rr.github.io/just-another-threat-monitoring-platform/extending/)), is on the [JATMP docs site](https://fj4rr.github.io/just-another-threat-monitoring-platform/).
