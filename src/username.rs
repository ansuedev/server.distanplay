//! Discord-style usernames: unique, lowercase, 2–32 characters of `a-z 0-9 _ .`,
//! no two dots in a row. The profile (display) name is free-form and separate.

use sqlx::{Postgres, Transaction};

pub fn is_valid(u: &str) -> bool {
    let n = u.chars().count();
    (2..=32).contains(&n)
        && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
        && !u.contains("..")
}

/// Best-effort conversion of any name into a valid username.
pub fn normalize(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.trim().to_lowercase().chars() {
        let c = match c {
            'a'..='z' | '0'..='9' | '_' | '.' => c,
            'á' | 'à' | 'ä' | 'â' | 'ã' => 'a',
            'é' | 'è' | 'ë' | 'ê' => 'e',
            'í' | 'ì' | 'ï' | 'î' => 'i',
            'ó' | 'ò' | 'ö' | 'ô' | 'õ' => 'o',
            'ú' | 'ù' | 'ü' | 'û' => 'u',
            'ñ' => 'n',
            'ç' => 'c',
            ' ' | '-' => '_',
            _ => continue,
        };
        if c == '.' && out.ends_with('.') {
            continue;
        }
        out.push(c);
    }
    let mut out: String = out.chars().take(32).collect();
    while out.chars().count() < 2 {
        out.push('_');
    }
    out
}

/// `wanted` if it's free, otherwise `wanted` plus the smallest number that is
/// ("anthony" → "anthony1" …), always within 32 characters.
pub async fn free_variant(tx: &mut Transaction<'_, Postgres>, wanted: &str) -> anyhow::Result<String> {
    let base = normalize(wanted);
    if !taken(tx, &base).await? {
        return Ok(base);
    }
    for n in 1..10_000u32 {
        let suffix = n.to_string();
        let head: String = base.chars().take(32 - suffix.len()).collect();
        let candidate = format!("{}{suffix}", head.trim_end_matches('.'));
        if is_valid(&candidate) && !taken(tx, &candidate).await? {
            return Ok(candidate);
        }
    }
    anyhow::bail!("no free username near {base}")
}

async fn taken(tx: &mut Transaction<'_, Postgres>, u: &str) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)").bind(u).fetch_one(&mut **tx).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(is_valid("anthony"));
        assert!(is_valid("a.b_c9"));
        assert!(!is_valid("A"));
        assert!(!is_valid("a..b"));
        assert!(!is_valid("Anthony"));
        assert_eq!(normalize("José Pérez"), "jose_perez");
        assert_eq!(normalize("x"), "x_");
        assert_eq!(normalize("a...b"), "a.b");
        assert!(is_valid(&normalize("Some Very Long Display Name That Goes On And On")));
    }
}
