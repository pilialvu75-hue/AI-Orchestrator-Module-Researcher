# Zero-cost operating envelope

Mandatory initial operating cost: **0 EUR/month**.

V1 requires only GitHub access plus an execution host chosen by the owner. No database,
queue, object store, hosted dashboard, model API or commercial scanner is required.

The repository intentionally avoids always-on paid infrastructure and recurring private
GitHub Actions scans. GitHub Actions is used for CI only. A scheduled one-shot scan can be
added later only after confirming it remains within the owner's free quota.

If a free quota is exhausted, the service must stop/degrade and preserve state. It must not
switch to billable APIs or resources.
