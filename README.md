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
- local auth-agent config, daemon, and client CLI
- shared fixture regeneration from `spec`
- non-relay program/runtime tests

## Auth Agent

The reference auth-agent daemon reads one JSON config file and listens on one local auth socket.

Example config:

```json
{
  "daemon": {
    "endpoint": "/tmp/overnet-auth.sock"
  },
  "identities": [
    {
      "identity_id": "default",
      "backend_type": "pass",
      "backend_config": {
        "entry": "overnet-priv-key"
      },
      "public_identity": {
        "scheme": "nostr.pubkey",
        "value": "274722f14ff06e2a790322ae1cee2d28c9cb0ffcd18d78d3bc7cca3f19e9764d"
      }
    }
  ],
  "policies": [
    {
      "identity_id": "default",
      "program_id": "irc.bridge",
      "locator": "irc://irc.example.test/overnet",
      "scope": "irc://irc.example.test/overnet",
      "action": "session.authenticate"
    },
    {
      "identity_id": "default",
      "program_id": "irc.bridge",
      "locator": "irc://irc.example.test/overnet",
      "scope": "irc://irc.example.test/overnet",
      "action": "session.delegate"
    }
  ]
}
```

Start the daemon with:

```bash
overnet-auth-agent.pl --config-file ~/.config/overnet/auth-agent.json
```

Query it with:

```bash
OVERNET_AUTH_SOCK=/tmp/overnet-auth.sock overnet-auth.pl identities
```

The generic client CLI also exposes:

```text
overnet-auth.pl authorize
overnet-auth.pl renew
overnet-auth.pl revoke
```

## Tests

Run the core test suite with:

```bash
prove -r t
```

Regenerate shared fixtures from `spec` with:

```bash
perl t/generate-fixtures.pl
```

Relay daemons, relay sync, deploy packaging, and the heavy IRC release gate now live in [relay-perl](https://github.com/overnet-project/relay-perl).

## Related Repositories

- [spec](https://github.com/overnet-project/spec)
- [relay-perl](https://github.com/overnet-project/relay-perl)
- [adapter-irc-perl](https://github.com/overnet-project/adapter-irc-perl)
- [irc-server](https://github.com/overnet-project/irc-server)

## Notes

Generated build artifacts and dependency caches are intentionally ignored by git.
