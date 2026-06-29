//! Credential generation: passwords from a configurable alphabet and
//! memorable `AdjectiveNoun` usernames. Pure logic, no UI.

use std::sync::LazyLock;

use rand::prelude::*;
use rust_embed::RustEmbed;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?";
/// Characters that read alike in most fonts.
const AMBIGUOUS: &str = "Il1O0o";

const ADJ_FILE: &str = "adjectives";
const NOUN_FILE: &str = "nouns";

/// Word lists baked into the binary at compile time.
#[derive(RustEmbed)]
#[folder = "assets/"]
struct Asset;

static ADJECTIVES: LazyLock<Vec<String>> = LazyLock::new(|| words(ADJ_FILE));
static NOUNS: LazyLock<Vec<String>> = LazyLock::new(|| words(NOUN_FILE));

fn words(path: &str) -> Vec<String> {
    let file = Asset::get(path).unwrap_or_else(|| panic!("missing embedded asset: {path}"));
    let text = std::str::from_utf8(&file.data).expect("embedded word list must be UTF-8");
    text.lines()
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Which character classes a password may draw from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Charset {
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for Charset {
    fn default() -> Self {
        Self {
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl Charset {
    /// The enabled character classes, ambiguous characters already stripped.
    fn pools(self) -> Vec<Vec<char>> {
        let keep = |s: &str| -> Vec<char> {
            s.chars()
                .filter(|c| !self.exclude_ambiguous || !AMBIGUOUS.contains(*c))
                .collect()
        };
        let mut pools = Vec::new();
        if self.lowercase {
            pools.push(keep(LOWERCASE));
        }
        if self.uppercase {
            pools.push(keep(UPPERCASE));
        }
        if self.digits {
            pools.push(keep(DIGITS));
        }
        if self.symbols {
            pools.push(keep(SYMBOLS));
        }
        pools.retain(|p| !p.is_empty());
        pools
    }

    /// Size of the combined alphabet, for entropy estimates.
    pub fn alphabet_size(self) -> usize {
        self.pools().iter().map(Vec::len).sum()
    }
}

/// Generate a password of `length` characters drawing from the enabled
/// classes. Guarantees at least one character from each enabled class (as far
/// as `length` allows). Returns `None` if no class is enabled or `length` is 0.
pub fn password(charset: Charset, length: usize, rng: &mut impl Rng) -> Option<String> {
    let pools = charset.pools();
    if pools.is_empty() || length == 0 {
        return None;
    }

    let alphabet: Vec<char> = pools.iter().flatten().copied().collect();
    let mut out: Vec<char> = Vec::with_capacity(length);

    // Seed one character per class so requirements are met, then fill the rest
    // from the whole alphabet and shuffle to hide that ordering.
    for pool in pools.iter().take(length) {
        out.push(*pool.choose(rng).expect("pools are non-empty"));
    }
    while out.len() < length {
        out.push(*alphabet.choose(rng).expect("alphabet is non-empty"));
    }
    out.shuffle(rng);
    Some(out.into_iter().collect())
}

/// A memorable `AdjectiveNoun` username, optionally suffixed with random digits.
pub fn username(suffix_digits: usize, rng: &mut impl Rng) -> String {
    let adj = ADJECTIVES.choose(rng).map_or("brave", String::as_str);
    let noun = NOUNS.choose(rng).map_or("otter", String::as_str);
    let mut name = format!("{}{}", title_case(adj), title_case(noun));
    for _ in 0..suffix_digits {
        name.push(char::from_digit(rng.random_range(0..10), 10).unwrap());
    }
    name
}

fn title_case(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Shannon entropy in bits for a password of `length` over `alphabet_size`.
pub fn entropy_bits(alphabet_size: usize, length: usize) -> f64 {
    if alphabet_size <= 1 || length == 0 {
        return 0.0;
    }
    (alphabet_size as f64).log2() * length as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_lists_loaded() {
        assert!(ADJECTIVES.len() > 100);
        assert!(NOUNS.len() > 100);
        assert!(ADJECTIVES.iter().all(|w| !w.contains(char::is_whitespace)));
    }

    #[test]
    fn respects_length_and_alphabet() {
        let mut rng = rand::rng();
        let cs = Charset::default();
        let pw = password(cs, 24, &mut rng).unwrap();
        assert_eq!(pw.chars().count(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn no_classes_is_none() {
        let mut rng = rand::rng();
        let cs = Charset {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(password(cs, 12, &mut rng).is_none());
    }

    #[test]
    fn excludes_ambiguous() {
        let mut rng = rand::rng();
        let cs = Charset {
            exclude_ambiguous: true,
            ..Charset::default()
        };
        for _ in 0..50 {
            let pw = password(cs, 32, &mut rng).unwrap();
            assert!(pw.chars().all(|c| !AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn username_has_digit_suffix() {
        let mut rng = rand::rng();
        let name = username(3, &mut rng);
        assert!(name.chars().rev().take(3).all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn username_without_suffix_is_alphabetic() {
        let mut rng = rand::rng();
        let name = username(0, &mut rng);
        assert!(!name.is_empty());
        assert!(name.chars().all(|c| c.is_ascii_alphabetic()));
        assert!(name.chars().next().unwrap().is_ascii_uppercase());
    }

    #[test]
    fn assets_are_embedded() {
        assert!(Asset::get(ADJ_FILE).is_some());
        assert!(Asset::get(NOUN_FILE).is_some());
        let names: Vec<_> = Asset::iter().collect();
        assert!(names.iter().any(|n| n == ADJ_FILE));
        assert!(names.iter().any(|n| n == NOUN_FILE));
    }

    #[test]
    fn single_class_uses_only_that_class() {
        let mut rng = rand::rng();
        let cs = Charset {
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let pw = password(cs, 16, &mut rng).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn length_below_class_count_is_honored() {
        let mut rng = rand::rng();
        // Four classes enabled but only room for two characters.
        let pw = password(Charset::default(), 2, &mut rng).unwrap();
        assert_eq!(pw.chars().count(), 2);
    }

    #[test]
    fn zero_length_is_none() {
        let mut rng = rand::rng();
        assert!(password(Charset::default(), 0, &mut rng).is_none());
    }

    #[test]
    fn title_case_capitalizes_first_only() {
        assert_eq!(title_case("brave"), "Brave");
        assert_eq!(title_case("OTTER"), "OTTER");
        assert_eq!(title_case(""), "");
    }

    #[test]
    fn entropy_grows_with_length_and_alphabet() {
        assert_eq!(entropy_bits(1, 100), 0.0);
        assert_eq!(entropy_bits(64, 0), 0.0);
        assert!(entropy_bits(26, 20) < entropy_bits(95, 20));
        assert!(entropy_bits(95, 10) < entropy_bits(95, 20));
        // 95 printable symbols, length 1 => log2(95) ~= 6.57 bits.
        assert!((entropy_bits(95, 1) - 6.57).abs() < 0.01);
    }
}
