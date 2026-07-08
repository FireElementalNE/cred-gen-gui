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

/// Draw one word uniformly from the combined adjective + noun pool, so each
/// word contributes log2(pool size) bits regardless of part of speech.
fn pool_word(rng: &mut impl Rng) -> &'static str {
    let index = rng.random_range(0..ADJECTIVES.len() + NOUNS.len());
    ADJECTIVES
        .get(index)
        .unwrap_or_else(|| &NOUNS[index - ADJECTIVES.len()])
}

/// A Diceware-style passphrase of `words` words drawn uniformly from the
/// combined embedded word pool, joined by `separator`. Returns `None` if
/// `words` is 0. Capitalization is applied uniformly and adds no entropy.
pub fn passphrase(
    words: usize,
    separator: char,
    capitalize: bool,
    rng: &mut impl Rng,
) -> Option<String> {
    if words == 0 {
        return None;
    }
    let parts: Vec<String> = (0..words)
        .map(|_| {
            let word = pool_word(rng);
            if capitalize {
                title_case(word)
            } else {
                word.to_owned()
            }
        })
        .collect();
    Some(parts.join(&separator.to_string()))
}

/// Entropy in bits of a passphrase of `words` uniform draws from the pool.
pub fn passphrase_entropy_bits(words: usize) -> f64 {
    if words == 0 {
        return 0.0;
    }
    ((ADJECTIVES.len() + NOUNS.len()) as f64).log2() * words as f64
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

/// Assumed attacker speed for crack-time estimates: a well-resourced offline
/// attack running ten billion guesses per second.
const CRACK_GUESSES_PER_SECOND: f64 = 1e10;

const SECONDS_PER_YEAR: f64 = 31_557_600.0;

/// Human-readable average time to brute-force a secret with `bits` of entropy
/// at [`CRACK_GUESSES_PER_SECOND`]. Average means half the keyspace searched.
pub fn crack_time(bits: f64) -> String {
    let seconds = bits.exp2() / 2.0 / CRACK_GUESSES_PER_SECOND;
    let years = seconds / SECONDS_PER_YEAR;
    if seconds < 1.0 {
        String::from("instantly")
    } else if seconds < 60.0 {
        format!("{seconds:.0} seconds")
    } else if seconds < 3_600.0 {
        format!("{:.0} minutes", seconds / 60.0)
    } else if seconds < 86_400.0 {
        format!("{:.0} hours", seconds / 3_600.0)
    } else if years < 1.0 {
        format!("{:.0} days", seconds / 86_400.0)
    } else if years < 100.0 {
        format!("{years:.0} years")
    } else if years < 10_000.0 {
        format!("{:.0} centuries", years / 100.0)
    } else if years < 1e6 {
        format!("{:.0} thousand years", years / 1e3)
    } else if years < 1e9 {
        format!("{:.0} million years", years / 1e6)
    } else if years < 1e12 {
        format!("{:.0} billion years", years / 1e9)
    } else if years < 1e15 {
        format!("{:.0} trillion years", years / 1e12)
    } else {
        format!("10^{:.0} years", years.log10().floor())
    }
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
    fn passphrase_has_word_count_and_separator() {
        let mut rng = rand::rng();
        let phrase = passphrase(4, '-', false, &mut rng).unwrap();
        let parts: Vec<&str> = phrase.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|w| !w.is_empty()));
        assert!(parts.iter().all(|w| w.chars().all(char::is_alphabetic)));
    }

    #[test]
    fn passphrase_capitalizes_each_word() {
        let mut rng = rand::rng();
        let phrase = passphrase(5, ' ', true, &mut rng).unwrap();
        for word in phrase.split(' ') {
            assert!(word.chars().next().unwrap().is_uppercase());
        }
    }

    #[test]
    fn zero_word_passphrase_is_none() {
        let mut rng = rand::rng();
        assert!(passphrase(0, '-', true, &mut rng).is_none());
    }

    #[test]
    fn passphrase_entropy_matches_pool_size() {
        assert_eq!(passphrase_entropy_bits(0), 0.0);
        let pool = (ADJECTIVES.len() + NOUNS.len()) as f64;
        let expected = pool.log2() * 5.0;
        assert!((passphrase_entropy_bits(5) - expected).abs() < 1e-9);
        assert!(passphrase_entropy_bits(6) > passphrase_entropy_bits(5));
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
    fn crack_time_scales_through_the_unit_ladder() {
        assert_eq!(crack_time(0.0), "instantly");
        // 2^40 / 2 / 1e10 = ~55 seconds.
        assert_eq!(crack_time(40.0), "55 seconds");
        // 2^50 / 2 / 1e10 = ~16 hours.
        assert_eq!(crack_time(50.0), "16 hours");
        // Full-charset defaults land far beyond named units.
        assert!(crack_time(128.0).starts_with("10^"));
        assert!(crack_time(80.0).contains("years") || crack_time(80.0).contains("centuries"));
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
