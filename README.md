# Overnet Core Perl

Perl reference implementation workspace for the shared Overnet core, authority, and program runtime layers.

GitHub: <https://github.com/overnet-project/core-perl>

This repository tracks the draft specifications in:

- [spec/docs/core.md](https://github.com/overnet-project/spec/blob/main/docs/core.md)
- [spec/docs/decisions.md](https://github.com/overnet-project/spec/blob/main/docs/decisions.md)
- [spec/fixtures/core/](https://github.com/overnet-project/spec/tree/main/fixtures/core)

## Status

This repo intentionally excludes the relay application and relay-heavy integration gate.

Current implemented scope:

- Overnet event parsing and validation
- required core tags and duplicate-tag handling
- JSON `content` envelope validation
- native versus adapted provenance checks
- kind `37800` state-event checks
- `7801` removal checks
- baseline removal authorization
- baseline delegation semantics for delegated removal
- hosted-channel authority helpers
- Overnet program runtime modules
- shared fixture regeneration from `spec`
- non-relay program/runtime tests

## Tests

Run the core test suite with:

```bash
/home/_73/.local/bin/plx prove -Ilib -Ilocal/lib/perl5 -r t
```

Regenerate shared fixtures from `spec` with:

```bash
/home/_73/.local/bin/plx perl -Ilib -Ilocal/lib/perl5 t/generate-fixtures.pl
```

Relay daemons, relay sync, deploy packaging, and the heavy IRC release gate now live in [relay-perl](https://github.com/overnet-project/relay-perl).

## Related Repositories

- [spec](https://github.com/overnet-project/spec)
- [relay-perl](https://github.com/overnet-project/relay-perl)
- [adapter-irc-perl](https://github.com/overnet-project/adapter-irc-perl)
- [irc-server](https://github.com/overnet-project/irc-server)

## Notes

Local Perl build artifacts in `.plx/` and `local/` are intentionally ignored by git.
