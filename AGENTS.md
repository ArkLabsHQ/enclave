# Agent guidelines

## Code layout

- In a Go file, put type definitions at the top, after the imports and
  constants.

- In a Go file, put functions that are not methods at the bottom, after the
  methods.

- Keep code comments short: one line where it will do.

- In a Go test file, put Test* functions above any helpers or type definitions.
