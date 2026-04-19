# Overnet Core Implementation

Perl reference implementation workspace for the current Overnet core validation surface.

This repository tracks the draft specifications in:

- `../overnet-spec/docs/core.md`
- `../overnet-spec/docs/decisions.md`
- `../overnet-spec/fixtures/core/`

## Status

This is an early reference implementation, not a complete Overnet stack.

Current implemented scope:

- Overnet event parsing and validation
- required core tags and duplicate-tag handling
- JSON `content` envelope validation
- native versus adapted provenance checks
- kind `37800` state-event checks
- `7801` removal checks
- baseline removal authorization
- baseline delegation semantics for delegated removal
- shared fixture regeneration from `overnet-spec`
- initial Overnet Program Runtime module scaffolding

This repository is intentionally narrow right now. It is acting as a conformance gate for the currently implemented core event model.

## What This Repo Is Not

This repository does not currently implement:

- a full Overnet relay
- a full client stack
- application profiles
- adapter implementations
- a complete Overnet Program Runtime behavior surface

Those concerns are expected to live in companion repositories.

## Tests

Run the core test suite with:

```bash
/home/_73/.local/bin/plx prove -Ilib -Ilocal/lib/perl5 -r t
```

Run the IRC verification path with:

```bash
/home/_73/.local/bin/plx prove -Ilib -Ilocal/lib/perl5 \
  t/spec-conformance-irc-server.t \
  t/program-irc-server.t \
  t/program-irc-server-relay.t
```

Regenerate shared fixtures from `overnet-spec` with:

```bash
/home/_73/.local/bin/plx perl -Ilib -Ilocal/lib/perl5 t/generate-fixtures.pl
```

## Notes

Local Perl build artifacts in `.plx/` and `local/` are intentionally ignored by git.
