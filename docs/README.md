# netscope docs

Long-form notes for the netscope agent that don't belong in the top-level `README.md` or in code comments.

Current layout:

- `architecture.md` — full architecture reference: the userspace↔kernel split, the BPF program/map inventory, the end-to-end scrape flow, external dependencies and kernel requirements, key design decisions, and deployment.
- `postmortems/` — incident and iteration retrospectives. Each file is dated and named after the thing being analyzed. The goal is recovery of context, not blame; future-us is the audience.
