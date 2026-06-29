# Credential Generator GUI

[![Build](https://img.shields.io/github/actions/workflow/status/FireElementalNE/cred-gen-gui/ci.yml?label=build)](https://github.com/FireElementalNE/cred-gen-gui/actions/workflows/ci.yml)
![Unsafe](https://img.shields.io/badge/unsafe-forbidden-red)

A small [egui](https://github.com/emilk/egui) desktop app for generating
passwords and memorable `AdjectiveNoun` usernames. A GUI reimagining of an old
CLI pet project.

- Configurable length and character classes (lowercase, uppercase, digits, symbols)
- Option to exclude look-alike characters (`Il1O0o`)
- Guarantees at least one character from each enabled class
- Live entropy estimate and strength meter
- One-click copy to clipboard

```sh
cargo run --release
```

> Built for fun and learning. Uses `rand`'s `ThreadRng` (a CSPRNG), but audit
> before trusting it with anything that matters.

