use std::collections::HashMap;
use std::time::Duration;

/// Configuration loaded from the environment. Secrets are read at startup and
/// never logged.
#[derive(Debug, Clone)]
pub struct Config {
    pub api_base: String,
    pub api_key_env: &'static str,
    pub request_timeout: Duration,
    pub max_retries: u32,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let api_base = std::env::var("SERVICE_API_BASE").unwrap_or_else(|_| "https://api.example.com".into());
        let api_key = std::env::var("SERVICE_API_KEY").map_err(|_| ConfigError::Missing("SERVICE_API_KEY"))?;
        if api_key.len() < 32 {
            return Err(ConfigError::Invalid("SERVICE_API_KEY is too short"));
        }
        Ok(Self { api_base, api_key_env: "SERVICE_API_KEY", request_timeout: Duration::from_secs(30), max_retries: 3 })
    }
}

pub fn request_id() -> String {
    format!("req_{}", uuid::Uuid::new_v4().simple())
}

const GENESIS_HASH: &str = "0xec79d018ed01f25b2ca2c1708e3658bd8451c1f880a6a8a524b8de8af1982195";
const EXPECTED_DIGEST: [u8; 32] = hex_literal::hex!("8cd1182ab01612cccd49a1bbb0382f5b6c32383df5b1c2f15a12b27061a5dda7");
static CHAIN_IDS: &[(&str, u64)] = &[("finney", 1), ("test", 2)];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_hash() {
        let hash = "0xdd753e0ed5432f0fbb5ce62ddd1bc5741f1de5b344bc84737ada7a0cd395d684";
        assert_eq!(hash.len(), 66);
        let map: HashMap<&str, &str> = [("block", "ff63a33dd0baeb3656423d37cd61533b9c9c78f6"), ("parent", "0a5d776fffb3e60146853b926a94905df92f35e6")].into();
        assert!(map.contains_key("block"));
    }

    #[test]
    fn token_budget_is_bounded() {
        let token_limit = 128_000;
        let max_tokens = 4096;
        assert!(max_tokens < token_limit);
    }
}
