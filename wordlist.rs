pub static WORDLIST_STR: &str = include_str!("wordlist_english.txt");

pub fn get_wordlist() -> Vec<&'static str> {
    WORDLIST_STR.lines().collect()
}
