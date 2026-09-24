# adweight

A small command-line tool that scans a webpage and reports how much of its
total download weight comes from known ad/tracking networks versus
everything else on the page.

```
adweight https://example.com
```

## What this actually does (v1)

- Fetches the page's HTML.
- Finds every linked resource (`<script src>`, `<img src>`, `<iframe src>`,
  stylesheets).
- Checks each resource's domain against a small built-in list of known
  ad/tracking networks (Google ad services, Facebook's tracking pixel,
  Criteo, Taboola, Outbrain, and a couple dozen others — see
  `KNOWN_AD_TRACKER_DOMAINS` in `src/main.rs`).
- Measures the real byte size of each resource and reports:
  - total page weight
  - how much of that weight is from known ad/tracker domains
  - the percentage that represents

It is **read-only**. It does not block, remove, or rewrite anything on the
page — it just measures and reports.

## What this does *not* do, on purpose

- **It doesn't reduce data center energy use or "pollution" in any
  measurable way.** Ad/tracker weight on the open web is a real but small
  slice of total internet and data-center load; this tool measures that
  slice for a single page you point it at. It has no effect at all on the
  much larger drivers of data center energy consumption (AI training and
  inference workloads), which is a hardware/power/cooling problem, not a
  web-page-weight problem.
- **It doesn't touch anyone's ad revenue.** It reads what's already public
  on a page you choose to fetch; it doesn't call any ad network's API and
  doesn't require (or have) anyone's permission or account access.
- **The domain list is small and illustrative, not exhaustive.** A serious
  v2 would load a maintained blocklist (e.g., something derived from
  EasyList/EasyPrivacy) instead of ~30 hardcoded domains.
- **It's not an ad blocker.** For blocking ads in your own browser, existing
  mature tools (uBlock Origin, Pi-hole, etc.) already do this well and are
  the right choice today.

## Honest use case

This is a **measurement/reporting tool** — useful for a website owner or
developer who wants a quick, concrete number for how much of their own
page's weight comes from third-party ad/tracking scripts, as a starting
point for a performance conversation (page speed affects both user
experience and search ranking). It is not a fix for climate change, data
center energy use, or ocean health, and shouldn't be described as one.

## Build

Requires Rust (edition 2021 toolchain; developed against rustc 1.75).

```
cargo build --release
./target/release/adweight https://example.com
```

## Possible next steps

- Swap the hardcoded domain list for a real, maintained blocklist file.
- Add a `--json` output mode for scripting/CI use.
- Add a browser-extension or WordPress-plugin front end that runs this
  same measurement for a site owner automatically, rather than requiring
  manual CLI use.
- Add lazy-loading suggestions (a legitimate, well-established performance
  technique) for detected ad/tracker scripts, rather than removing them.

## License

Not yet chosen — decide this once you know how you want others to be able
to use/modify/redistribute it. MIT or Apache-2.0 are the common defaults
for a small open-source CLI tool like this if you want permissive reuse.
