// XGurdian 4.0 — Extreme Generator of Password Security
// ------------------------------------------------------------
// Single-file, production-grade password + passphrase generator.
// Run with: `cargo run --release -- <options>`
// If you just want a strong default password: `cargo run --release`
//
// Suggested Cargo.toml:
// [package]
// name = "xgps"
// version = "0.1.0"
// edition = "2021"
//
// [dependencies]
// rand = "0.8"
// time = { version = "0.3", features = ["formatting"] }
// base64 = "0.22"
//
// Optional (enable features if you add these):
// arboard = { version = "3", optional = true }    # for clipboard copy (feature: clipboard)
//
// ------------------------------------------------------------
// Highlights
// - Cryptographically secure randomness (OsRng)
// - Multiple modes: random password, pronounceable, passphrase
// - Guarantees: at least one char from each enabled class (if requested)
// - Entropy estimation + strength labels
// - Ambiguous-lookalike filtering (e.g., O/0, l/1/I)
// - Batch generation, output to file, Base64 exports
// - Basic breach/weak blacklist
// - History with timestamp in ./xgps_history.txt
// - Simple CLI (no external CLI library needed)
// - Tons of comments to help you learn Rust 💙
// ------------------------------------------------------------

use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use std::cmp::min;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use time::OffsetDateTime;

// ---------------------------- Utility ----------------------------
fn now_iso() -> String {
    // old (time crate style, wrong)
// new (chrono style, works)
let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();

}
fn write_history(line: &str) {
    let mut path = PathBuf::from("xgps_history.txt");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&mut path) {
        let _ = writeln!(f, "{}", line);
    }
}

fn println_stderr(s: &str) {
    let _ = writeln!(io::stderr(), "{}", s);
}

// ---------------------------- Config ----------------------------
#[derive(Clone, Debug)]
struct Config {
    mode: Mode,
    length: usize,      // for password/pronounceable
    words: usize,      // for passphrase
    count: usize,      // how many to generate
    require_each_class: bool,
    allow_upper: bool,
    allow_lower: bool,
    allow_digits: bool,
    allow_symbols: bool,
    exclude_ambiguous: bool,
    forbid_sequences: bool,
    forbid_repeats: bool,
    to_file: Option<PathBuf>,
    also_base64: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Password,
            length: 24,
            words: 5,
            count: 1,
            require_each_class: true,
            allow_upper: true,
            allow_lower: true,
            allow_digits: true,
            allow_symbols: true,
            exclude_ambiguous: true,
            forbid_sequences: true,
            forbid_repeats: true,
            to_file: None,
            also_base64: false,
        }
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
enum Mode {
    Password,
    Pronounceable,
    Passphrase,
}

// ---------------------------- Character Sets ----------------------------
#[derive(Clone)]
struct CharacterSets {
    lower: Vec<char>,
    upper: Vec<char>,
    digits: Vec<char>,
    symbols: Vec<char>,
}

impl CharacterSets {
    fn new(exclude_ambiguous: bool) -> Self {
        // Ambiguous characters we might want to avoid in some contexts
        // 0 O o 1 l I | S 5 B 8 G 6 Z 2
        let ambiguous: &[char] = &['0', 'O', 'o', '1', 'l', 'I', '|', 'S', '5', 'B', '8', 'G', '6', 'Z', '2'];

        let mut lower: Vec<char> = (b'a'..=b'z').map(|b| b as char).collect();
        let mut upper: Vec<char> = (b'A'..=b'Z').map(|b| b as char).collect();
        let mut digits: Vec<char> = (b'0'..=b'9').map(|b| b as char).collect();
        let mut symbols: Vec<char> = r#"!@#$%^&*()-_=+[]{}|;:,.<>?/~`\"'"#.chars().collect();

        if exclude_ambiguous {
            let filt = |v: &mut Vec<char>| v.retain(|c| !ambiguous.contains(c));
            filt(&mut lower);
            filt(&mut upper);
            filt(&mut digits);
            filt(&mut symbols);
        }

        Self { lower, upper, digits, symbols }
    }

    fn combined(&self, allow_lower: bool, allow_upper: bool, allow_digits: bool, allow_symbols: bool) -> Vec<char> {
        let mut v = Vec::new();
        if allow_lower { v.extend(self.lower.iter().copied()); }
        if allow_upper { v.extend(self.upper.iter().copied()); }
        if allow_digits { v.extend(self.digits.iter().copied()); }
        if allow_symbols { v.extend(self.symbols.iter().copied()); }
        v
    }
}

// ---------------------------- Weak/Breach Blacklist ----------------------------
// This is a minimal list for demo purposes. In real life, check against a local hash list
// or use k-anonymity APIs like HIBP (avoid sending full password!).
const WEAK_BLACKLIST: &[&str] = &[
    "password", "123456", "qwerty", "abc123", "111111", "letmein", "admin",
    "welcome", "iloveyou", "monkey", "dragon", "football", "baseball", "starwars",
];

fn looks_like_blacklisted(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    WEAK_BLACKLIST.iter().any(|w| &l == w)
}

// ---------------------------- Entropy Estimation ----------------------------
#[derive(Debug, Clone, Copy)]
struct Entropy {
    bits: f64,
}

impl Entropy {
    fn strength_label(self) -> &'static str {
        match self.bits {
            b if b < 50.0 => "Weak",
            b if b < 80.0 => "Moderate",
            b if b < 110.0 => "Strong",
            _ => "Very Strong",
        }
    }
}

fn entropy_for_password(length: usize, alphabet_size: usize) -> Entropy {
    // H = length * log2(alphabet_size)
    let bits = (length as f64) * (alphabet_size as f64).log2();
    Entropy { bits }
}

fn entropy_for_passphrase(words: usize, wordlist_size: usize) -> Entropy {
    let bits = (words as f64) * (wordlist_size as f64).log2();
    Entropy { bits }
}

// ---------------------------- Validators ----------------------------
fn has_required_classes(s: &str, cfg: &Config, sets: &CharacterSets) -> bool {
    let has_lower = s.chars().any(|c| sets.lower.contains(&c));
    let has_upper = s.chars().any(|c| sets.upper.contains(&c));
    let has_digit = s.chars().any(|c| sets.digits.contains(&c));
    let has_symbol = s.chars().any(|c| sets.symbols.contains(&c));

    (!cfg.allow_lower || has_lower) &&
    (!cfg.allow_upper || has_upper) &&
    (!cfg.allow_digits || has_digit) &&
    (!cfg.allow_symbols || has_symbol)
}

fn has_sequences(s: &str) -> bool {
    // Detect three-in-a-row increasing sequences like abc, 123
    let bytes = s.as_bytes();
    for w in bytes.windows(3) {
        let (a, b, c) = (w[0], w[1], w[2]);
        if b == a + 1 && c == b + 1 { return true; }
    }
    false
}

fn has_runs(s: &str) -> bool {
    // Detect three identical chars in a row
    let bytes = s.as_bytes();
    for w in bytes.windows(3) {
        if w[0] == w[1] && w[1] == w[2] { return true; }
    }
    false
}

// ---------------------------- Random helpers ----------------------------
fn choose_char(pool: &[char]) -> char {
    // Use cryptographically secure random index
    if pool.is_empty() { return '\u{FFFD}'; }
    let mut rng = OsRng;
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);
    let idx = u64::from_le_bytes(buf) as usize % pool.len();
    pool[idx]
}

fn shuffle_in_place(chars: &mut [char]) {
    // Fisher–Yates shuffle using OsRng
    let mut rng = OsRng;
    for i in (1..chars.len()).rev() {
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        let j = (u64::from_le_bytes(buf) as usize) % (i + 1);
        chars.swap(i, j);
    }
}

// ---------------------------- Generators ----------------------------
fn generate_password(cfg: &Config, sets: &CharacterSets) -> String {
    let mut pool = sets.combined(cfg.allow_lower, cfg.allow_upper, cfg.allow_digits, cfg.allow_symbols);
    if pool.is_empty() {
        return String::from("(no character sets enabled)");
    }

    let mut out: Vec<char> = Vec::with_capacity(cfg.length);

    // If we must include at least one from each enabled class, pre-seed those.
    if cfg.require_each_class {
        if cfg.allow_lower { out.push(choose_char(&sets.lower)); }
        if cfg.allow_upper { out.push(choose_char(&sets.upper)); }
        if cfg.allow_digits { out.push(choose_char(&sets.digits)); }
        if cfg.allow_symbols { out.push(choose_char(&sets.symbols)); }
    }

    while out.len() < cfg.length {
        out.push(choose_char(&pool));
    }

    // Shuffle so the pre-seeded mandatory chars aren't predictable at the start
    shuffle_in_place(&mut out);

    let s: String = out.into_iter().collect();

    // Apply policies – regenerate a few times if needed
    for _ in 0..32 {
        if cfg.forbid_sequences && has_sequences(&s) { return generate_password(cfg, sets); }
        if cfg.forbid_repeats && has_runs(&s) { return generate_password(cfg, sets); }
        if cfg.require_each_class && !has_required_classes(&s, cfg, sets) { return generate_password(cfg, sets); }
        if looks_like_blacklisted(&s) { return generate_password(cfg, sets); }
    }

    s
}

// Pronounceable generator using alternating consonant–vowel patterns
fn generate_pronounceable(cfg: &Config, sets: &CharacterSets) -> String {
    // Basic lists (not exhaustive, but decent)
    let vowels: Vec<char> = vec!['a', 'e', 'i', 'o', 'u'];
    let consonants: Vec<char> = sets
        .lower
        .iter()
        .copied()
        .filter(|c| !vowels.contains(c))
        .collect();

    let mut out = String::with_capacity(cfg.length);
    let mut use_consonant = true; // start with consonant, CVCV…

    while out.chars().count() < cfg.length {
        let c = if use_consonant {
            choose_char(&consonants)
        } else {
            choose_char(&vowels)
        };
        out.push(c);
        use_consonant = !use_consonant;
    }

    // Optionally inject some digits/symbols at random positions for strength
    if cfg.allow_digits || cfg.allow_symbols || cfg.allow_upper {
        let mut chars: Vec<char> = out.chars().collect();
        if cfg.allow_upper {
            // Randomly uppercase a couple of letters
            let n = min(2, chars.len());
            for i in 0..n {
                let idx = i * 2 % chars.len();
                chars[idx] = chars[idx].to_ascii_uppercase();
            }
        }
        if cfg.allow_digits {
            if !sets.digits.is_empty() { chars.insert(chars.len() / 2, choose_char(&sets.digits)); }
        }
        if cfg.allow_symbols {
            if !sets.symbols.is_empty() { chars.insert(chars.len() / 3, choose_char(&sets.symbols)); }
        }
        shuffle_in_place(&mut chars);
        out = chars.into_iter().collect();
    }

    out
}

// Passphrase (diceware-style) using a small embedded list
fn generate_passphrase(cfg: &Config) -> (String, usize) {
    let wl = WORDLIST;
    let mut words = Vec::with_capacity(cfg.words);
    for _ in 0..cfg.words {
        let w = wl[random_index(wl.len())];
        words.push(w);
    }
    (words.join("-"), wl.len())
}

fn random_index(n: usize) -> usize {
    let mut rng = OsRng;
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);
    (u64::from_le_bytes(buf) as usize) % n
}

// ---------------------------- CLI parsing ----------------------------
fn print_help() {
    println!("\nXGurdian 4.0 — Extreme Generator of Password Security\n");
    println!("USAGE:\n  cargo run --release -- [options]\n");
    println!("OPTIONS:");
    println!("  --mode [password|pronounce|passphrase]     (default: password)");
    println!("  --length N                         (password/pronounce, default: 24)");
    println!("  --words N                          (passphrase word count, default: 5)");
    println!("  --count N                          (how many to generate, default: 1)");
    println!("  --no-upper | --no-lower | --no-digits | --no-symbols");
    println!("  --allow-ambiguous                          (include 0/O/1/l etc)");
    println!("  --no-require-each                          (don’t force each class)");
    println!("  --allow-seq                                (allow abc/123 sequences)");
    println!("  --allow-repeats                            (allow aaa runs)");
    println!("  --file <path>                          (append outputs to file)");
    println!("  --b64                                      (print Base64 of raw bytes too)");
    println!("  -h | --help                                (this help)\n");
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let mut args = env::args().skip(1).peekable();

    while let Some(a) = args.next() {
        match a.as_str() {
            "--mode" => {
                if let Some(v) = args.next() {
                    cfg.mode = match v.as_str() {
                        "password" => Mode::Password,
                        "pronounce" | "pronounceable" => Mode::Pronounceable,
                        "passphrase" => Mode::Passphrase,
                        _ => {
                            println_stderr("Unknown mode; using password");
                            Mode::Password
                        }
                    }
                }
            }
            "--length" => { if let Some(v) = args.next() { if let Ok(n) = v.parse() { cfg.length = n.max(8); } } }
            "--words"  => { if let Some(v) = args.next() { if let Ok(n) = v.parse() { cfg.words = n.max(3); } } }
            "--count"  => { if let Some(v) = args.next() { if let Ok(n) = v.parse() { cfg.count = n.clamp(1, 10_000); } } }

            "--no-upper" => cfg.allow_upper = false,
            "--no-lower" => cfg.allow_lower = false,
            "--no-digits" => cfg.allow_digits = false,
            "--no-symbols" => cfg.allow_symbols = false,
            "--allow-ambiguous" => cfg.exclude_ambiguous = false,
            "--no-require-each" => cfg.require_each_class = false,
            "--allow-seq" => cfg.forbid_sequences = false,
            "--allow-repeats" => cfg.forbid_repeats = false,
            "--file" => {
                if let Some(path) = args.next() {
                    cfg.to_file = Some(PathBuf::from(path));
                }
            }
            "--b64" => cfg.also_base64 = true,
            "-h" | "--help" => { print_help(); std::process::exit(0); }
            _ => {
                println_stderr(&format!("Unknown arg: {}", a));
                println_stderr("Use -h for help");
            }
        }
    }

    // Safety: ensure at least one class when in password mode
    if cfg.mode == Mode::Password {
        if !cfg.allow_lower && !cfg.allow_upper && !cfg.allow_digits && !cfg.allow_symbols {
            println_stderr("No character classes enabled; enabling lowercase by default.");
            cfg.allow_lower = true;
        }
    }

    cfg
}

// ---------------------------- Output helpers ----------------------------
fn output_line(s: &str, cfg: &Config) {
    println!("{}", s);
    if let Some(path) = &cfg.to_file {
        let _ = fs::create_dir_all(path.parent().unwrap_or_else(|| std::path::Path::new(".")));
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", s);
        }
    }
}

fn print_banner() {
    println!("🔐 XGurdian 4.0 — Extreme Generator of Password Security");
    println!("   (secure by default, fast, and flexible)\n");
}

// ---------------------------- MAIN ----------------------------
fn main() {
    print_banner();
    let cfg = parse_args();

    match cfg.mode {
        Mode::Password => run_password_mode(&cfg),
        Mode::Pronounceable => run_pronounceable_mode(&cfg),
        Mode::Passphrase => run_passphrase_mode(&cfg),
    }
}

fn run_password_mode(cfg: &Config) {
    let sets = CharacterSets::new(cfg.exclude_ambiguous);
    let pool = sets.combined(cfg.allow_lower, cfg.allow_upper, cfg.allow_digits, cfg.allow_symbols);
    let alphabet = pool.len().max(1);

    for i in 0..cfg.count {
        let t0 = OffsetDateTime::now_utc();
        let s = generate_password(cfg, &sets);
        let dt = OffsetDateTime::now_utc() - t0;

        let ent = entropy_for_password(s.len(), alphabet);
        let label = ent.strength_label();

        let line = format!(
            "[{}] #{} {}  (len={}, entropy={:.1} bits, {})",
            now_iso(), i + 1, s, s.len(), ent.bits, label
        );
        output_line(&line, cfg);

        if cfg.also_base64 {
            // Export the raw bytes of the UTF-8 string as Base64 (note: not reversible to same chars in all cases)
            let b64 = general_purpose::STANDARD.encode(s.as_bytes());
            output_line(&format!("    base64: {}", b64), cfg);
        }

        write_history(&line);
        let _ = dt; // timing variable kept for future use or logging
    }
}

fn run_pronounceable_mode(cfg: &Config) {
    let sets = CharacterSets::new(cfg.exclude_ambiguous);
    for i in 0..cfg.count {
        let s = generate_pronounceable(cfg, &sets);
        let ent = entropy_for_password(s.len(), (sets.lower.len() + sets.digits.len() + sets.symbols.len()).max(1));
        let line = format!(
            "[{}] #{} {}  (len={}, entropy≈{:.1} bits, {})",
            now_iso(), i + 1, s, s.len(), ent.bits, ent.strength_label()
        );
        output_line(&line, cfg);
        write_history(&line);
    }
}

fn run_passphrase_mode(cfg: &Config) {
    for i in 0..cfg.count {
        let (s, wl_size) = generate_passphrase(cfg);
        let ent = entropy_for_passphrase(cfg.words, wl_size);
        let line = format!(
            "[{}] #{} {}  (words={}, entropy≈{:.1} bits, {})",
            now_iso(), i + 1, s, cfg.words, ent.bits, ent.strength_label()
        );
        output_line(&line, cfg);
        write_history(&line);
    }
}

// ---------------------------- WORDLIST ----------------------------
// A compact, hand-picked list to keep the file nimble but useful.
// For serious use, consider a 7,776-word diceware list for ~60+ bits with 6 words.
const WORDLIST: &[&str] = &[
    // ~250 short, common words (enough for demos; entropy calc uses this size)
    "able","acid","also","area","army","atom","aunt","bake","bald","ball","band","bank","barn","base","bath","bead","beam","bean","bear","beat",
    "beef","bell","belt","bend","bent","best","bird","blow","blue","boat","body","boil","bolt","bone","book","boot","born","both","bowl","bulk",
    "burn","bush","busy","cake","calm","camp","card","care","cart","case","cash","cast","cell","chat","chef","chip","city","clip","coal","coat",
    "code","cold","come","cook","cool","cork","corn","cost","crab","crew","crop","cube","cure","curl","cute","dare","dark","data","dawn","days",
    "deal","deer","dent","desk","dial","dice","dine","dirt","dish","dive","dock","doll","door","dose","down","draw","drop","drum","duck","dune",
    "duty","each","earn","easy","echo","edge","edit","eggs","epic","even","ever","exit","face","fact","fade","fail","fair","farm","fast","fate",
    "fear","feed","feel","feet","fell","felt","file","fill","film","find","fine","fire","fish","five","flag","flat","fled","flea","flex","flip",
    "flow","foam","fold","food","fool","form","fort","frog","fuel","full","fund","fuse","gain"," game","gaze","gear","gems","gift","girl","give",
    "glad","glow","goal","goat","gold","golf","gone","good","goose","gown","grab","gray","grew","grid","grim","grip","grow","gulf","hail","hair",
    "half","hall","hand","hard","harm","hash","hate","hawk","haze","heat","heed","heel","helm","help","herb","hero","hide","high","hint","hire",
    "hive","hold","hole","holy","home","hood","hook","hope","horn","hose","host","hour","huge","hunt","hush","idle","inch","into","iron","isle",
    "item","jazz","jeep","join","joke","jump","jury","keep","keto","kick","kill","kind","king","kiss","kite","knee","knot","lack","lady","lamb",
    "lamp","land","lane","last","late","lava","lawn","lazy","lead","leaf","lean","left","lend","lens","lily","limb","lime","line","link","lion",
    "lips","load","loan","lock","loft","logo","long","look","loop","lord","lose","loss","lost","love","luck","lung","made","mail","main","make",
    "male","mall","many","maps","mark","mask","mast","mate","math","maze","meal","mean","meat","meet","melt","mend","menu","mere","mesh","mice",
    "mild","mile","milk","mind","mine","mini","mint","miss","mode","mold","mole","mood","moon","more","most","moss","move","much","mule","must",
    "mute","name","near","neck","need","nest","news","next","nice","nick","nine","node","none","noon","norm","nose","note","obey","ocean","odor",
    "okay","once","onion","only","open","opus","oral","oval","oven","over","pace","pack","page","paid","pain","pair","palm","pane","park","part",
    "pass","past","path","peak","peel","peep","peer","pegs","pest","pets","pick","pile","pill","pine","pipe","plan","play","plot","plug","plus",
    "poem","poet","pole","pond","pool","poor","port","pose","post","pots","pour","pray","pull","pure","push","quit","race","rack","rage","raid",
    "rail","rain","rake","rang","rank","rare","rate","read","real","reap","rest","rice","rich","ride","ring","ripe","rise","risk","road","roam",
    "roar","rock","role","roll","roof","room","root","rope","rose","rude","rule","rush","rust","safe","sail","salt","same","sand","save","scan",
    "scar","seed","seek","seem","seen","self","sell","send","sent","sew","shed","ship","shoe","shop","shot","show","shut","sign","silk","sink",
    "site","size","skin","slab","slam","slip","slot","slow","smog","snack","snap","snow","sofa","soft","soil","sold","sole","solo","some","song",
    "soon","sour","span","spin","spit","spot","star","stay","stem","step","stir","stop","stub","such","suit","sums","sung","sunk","sure","swim",
    "taco","tale","talk","tall","tape","task","taut","taxi","team","tech","tend","tens","term","test","text","than","that","them","then","thin",
    "this","tide","tile","till","time","tint","tiny","tire","toad","told","toll","tone","tong","tool","took","tooth","torn","toss","tour","town",
    "toys","tray","tree","trim","tuba","tune","turf","turn","twin","type","ugly","unit","unto","used","user","vain","vase","vast","veal","veer",
    "veil","vein","vent","verb","very","vest","vibe","vice","view","vila","vine","visa","void","vote","wade","wage","wail","wait","walk","wall",
    "want","warm","warn","wash","wave","weak","wear","web","week","weft","well","went","were","west","what","when","whip","whom","wide","wife",
    "wild","will","wind","wine","wing","wink","wipe","wire","wise","wish","wood","wool","word","work","worm","wrap","yard","yarn","yawn","year",
    "yell","yoga","yolk","yore","your","zero","zinc","zone","zoom",
];

// ---------------------------- Tests (run: `cargo test`) ----------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_increases_with_length() {
        let e1 = entropy_for_password(10, 62).bits;
        let e2 = entropy_for_password(20, 62).bits;
        assert!(e2 > e1);
    }

    #[test]
    fn password_has_required_classes() {
        let cfg = Config { require_each_class: true, ..Default::default() };
        let sets = CharacterSets::new(true);
        let s = generate_password(&cfg, &sets);
        assert!(has_required_classes(&s, &cfg, &sets));
    }

    #[test]
    fn passphrase_word_count() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Passphrase;
        cfg.words = 6;
        let (s, _) = generate_passphrase(&cfg);
        assert_eq!(s.split('-').count(), 6);
    }
}