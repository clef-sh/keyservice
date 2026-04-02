# @clef-sh/keyservice-linux-x64

Bundled [clef-keyservice](https://github.com/clef-sh/keyservice) binary for **Linux x64**.

This package is an implementation detail of [Clef](https://github.com/clef-sh/clef) — a
git-native secrets management tool built on Mozilla SOPS. You should not need to install it
directly.

## How it works

`@clef-sh/cli` declares this package as an `optionalDependency`. When you run `npm install` on
a Linux x64 machine, npm automatically installs this package and Clef resolves the bundled
binary at runtime — no separate installation required.

## Versioning

This package is versioned by the **clef-keyservice version** it contains. Platform packages are
published independently of `@clef-sh/core` and `@clef-sh/cli`.

## License

The clef-keyservice binary is licensed under the
[Business Source License 1.1](https://github.com/clef-sh/keyservice/blob/main/LICENSE) (see `LICENSE`).

## Parent project

- Repository: https://github.com/clef-sh/keyservice
- Documentation: https://clef.sh
- CLI package: [@clef-sh/cli](https://www.npmjs.com/package/@clef-sh/cli)
