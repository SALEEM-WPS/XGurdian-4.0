#🔐 XGurdian 4.0
Extreme Generator of Password Security — A single-file, production-grade password + passphrase generator written in Rust.

XGurdian is designed to create cryptographically secure passwords, pronounceable passwords, and passphrases. It comes with built-in entropy estimation, weak password detection, history logging, and flexible CLI options.

#✨ Features

🔑 Secure randomness (using OsRng)

🔄 Multiple modes: random password, pronounceable, and passphrase

✅ Guarantees at least one character from each enabled class (optional)

📊 Entropy estimation + strength labels (Weak / Moderate / Strong / Very Strong)

🚫 Ambiguous character filtering (0/O, l/1/I, etc.)

📚 Batch generation + optional file output

🔒 Minimal weak/breach blacklist

🕑 History logging with timestamps (xgps_history.txt)

📦 Single-file CLI, no external CLI libraries needed

💙 Well-documented to help you learn Rust

#📦 Installation

Clone this repository and build with Cargo:

git clone https://github.com/yourname/xgurdian.git
cd xgurdian
cargo build --release


Run the generator:

cargo run --release

🚀 Usage
cargo run --release -- [options]

#Options
Option	Description
`--mode [password	pronounce
--length N	Password/pronounceable length (default: 24)
--words N	Passphrase word count (default: 5)
--count N	Number of outputs to generate (default: 1)
--no-upper / --no-lower / --no-digits / --no-symbols	Disable specific classes
--allow-ambiguous	Allow characters like 0/O/1/l
--no-require-each	Don’t force each enabled class
--allow-seq	Allow sequences (abc, 123)
--allow-repeats	Allow repeated runs (aaa)
--file <path>	Append outputs to a file
--b64	Output Base64 representation
-h, --help	Show help
🔍 Examples

Generate a strong random password (default 24 chars):

cargo run --release


Generate 3 pronounceable passwords of length 12:

cargo run --release --mode pronounce --length 12 --count 3


Generate a 6-word passphrase:

cargo run --release --mode passphrase --words 6


Export 5 passwords to a file:

cargo run --release --count 5 --file output.txt

#📊 Entropy Strength Labels

< 50 bits → Weak ⚠️

50–79 bits → Moderate 🟡

80–109 bits → Strong 🟢

110+ bits → Very Strong 🔵

#📝 History

Every generated password/passphrase is appended to xgps_history.txt with a UTC timestamp.
#📖 Notes

This project ships with a compact embedded wordlist (~250 words) for demo purposes.

For serious passphrase use, consider integrating a Diceware list (~7,776 words).

XGurdian avoids common weak passwords via a minimal blacklist (password, 123456, qwerty, etc.)
