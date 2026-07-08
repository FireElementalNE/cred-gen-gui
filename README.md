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
- Optional Random.org entropy mixing (remote seed is SHA-256-mixed with OS
  randomness, never used alone)

```sh
cargo run --release
```

> Built for fun and learning. Generation draws from the OS CSPRNG (`rand`'s
> `SysRng`); with the Random.org option enabled, a remote seed is hashed
> together with OS randomness to seed a `StdRng`. Audit before trusting it
> with anything that matters.

