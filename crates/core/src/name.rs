//! The deceptive-character law for every user-visible name: node names in the
//! engine and grantee names on a ledger row share this one set.

/// Whether the character reorders, hides or breaks the rest of the name when a
/// host draws it. `char::is_control` is category `Cc` only and misses all of
/// these.
///
/// U+200C and U+200D sit between the refused code points and are admitted:
/// the non-joiner is mandatory orthography in Persian, Urdu and Kurdish, and
/// the joiner builds Indic conjuncts and every multi-person emoji, so a
/// refusal would deny whole scripts a name.
pub fn is_deceptive(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' // soft hyphen
            | '\u{061C}' // arabic letter mark
            | '\u{200B}' // zero-width space
            | '\u{200E}' | '\u{200F}' // LRM/RLM
            | '\u{2028}' | '\u{2029}' // line and paragraph separators
            | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
            | '\u{2060}' // word joiner
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}' // zero-width no-break space
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_joiners_pass_and_their_neighbours_do_not() {
        assert!(is_deceptive('\u{200B}'));
        assert!(!is_deceptive('\u{200C}'));
        assert!(!is_deceptive('\u{200D}'));
        assert!(is_deceptive('\u{200E}'));
        assert!(!is_deceptive('a'));
    }
}
