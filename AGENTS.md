# Agent guidelines

## Code layout

- In a Go file, put functions that are not methods at the bottom, after the
  methods.

- In a Go test file, put Test* functions above any helpers or type definitions.

## Naming

- Name variables, parameters, functions and types after what they mean in the
  domain, for example `readVersion`, `insertIfEarliest`, `GenerationState`.
  Avoid generic names such as `visit`, `handle`, `process`, `data` or a bare
  `State`, and don't reuse a name that already means something else nearby.
