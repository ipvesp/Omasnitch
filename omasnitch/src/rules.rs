use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{
        Path,
        PathBuf,
    },
};

use anyhow::{
    Context,
    Result,
};

use serde::{
    Deserialize,
    Serialize,
};

use crate::model::{
    Rule,
    RuleAction,
};

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
pub struct RuleStore {
    pub rules:
        HashMap<String, RuleAction>,
    #[serde(default)]
    pub profiles: HashMap<String, HashMap<String, RuleAction>>,
    #[serde(default = "default_profile")]
    pub active_profile: String,
    #[serde(default)]
    pub prompt_uid: Option<u32>,
}

fn default_profile() -> String { "Home".to_string() }

impl Default for RuleStore {
    fn default() -> Self {
        Self { rules: HashMap::new(), profiles: HashMap::new(), active_profile: default_profile(), prompt_uid: None }
    }
}

impl RuleStore {
    pub fn load(
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let path =
            path.as_ref();

        if !path.exists() {
            return Ok(Self::default());
        }

        let data =
            fs::read_to_string(path)
                .with_context(|| {
                    format!(
                        "failed to read {}",
                        path.display()
                    )
                })?;

        let mut store: Self =
            serde_json::from_str(
                &data,
            )
            .context(
                "failed to parse rules"
            )?;

        if store.active_profile.is_empty() {
            store.active_profile = default_profile();
        }
        Ok(store)
    }

    pub fn save(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let path =
            path.as_ref();

        if let Some(parent) =
            path.parent()
        {
            fs::create_dir_all(
                parent,
            )?;
        }

        let tmp =
            PathBuf::from(
                format!(
                    "{}.tmp",
                    path.display()
                ),
            );

        let data =
            serde_json::to_vec_pretty(
                self,
            )?;

        fs::write(
            &tmp,
            data,
        )?;

        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;

        fs::rename(
            tmp,
            path,
        )?;

        Ok(())
    }

    pub fn set(
        &mut self,
        app: String,
        action: RuleAction,
    ) {
        self.rules.insert(
            app,
            action,
        );
    }

    pub fn profiles(&self) -> Vec<String> {
        let mut names = vec!["Home".to_string(), "Work".to_string(), "Public Wi-Fi".to_string()];
        for name in self.profiles.keys() {
            if !names.contains(name) { names.push(name.clone()); }
        }
        names
    }

    pub fn switch_profile(&mut self, name: String) -> Result<()> {
        if !self.profiles().contains(&name) {
            anyhow::bail!("unknown profile");
        }
        if name == self.active_profile { return Ok(()); }
        self.profiles.insert(self.active_profile.clone(), self.rules.clone());
        self.rules = self.profiles.get(&name).cloned().unwrap_or_default();
        self.active_profile = name;
        Ok(())
    }

    pub fn remove(
        &mut self,
        app: &str,
    ) {
        self.rules.remove(app);
    }

    pub fn list(
        &self,
    ) -> Vec<Rule> {
        let mut out =
            self
                .rules
                .iter()
                .map(
                    |(application, action)| {
                        Rule {
                            application:
                                application.clone(),
                            action:
                                action.clone(),
                        }
                    },
                )
                .collect::<Vec<_>>();

        out.sort_by(
            |a, b| {
                a.application
                    .cmp(
                        &b.application
                    )
            },
        );

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn migrates_old_rules_and_keeps_profiles_independent() {
        let mut store: RuleStore = serde_json::from_str(
            r#"{"rules":{"firefox":"block"}}"#
        ).unwrap();
        assert_eq!(store.active_profile, "Home");
        store.switch_profile("Work".to_string()).unwrap();
        assert!(store.rules.is_empty());
        store.set("firefox".to_string(), RuleAction::Allow);
        store.switch_profile("Home".to_string()).unwrap();
        assert!(matches!(store.rules.get("firefox"), Some(RuleAction::Block)));
        store.switch_profile("Work".to_string()).unwrap();
        assert!(matches!(store.rules.get("firefox"), Some(RuleAction::Allow)));
    }

    #[test]
    fn saves_rules_with_owner_only_permissions() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("omasnitch-rules-{}-{unique}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("rules.json");
        let tmp = dir.join("rules.json.tmp");
        fs::write(&tmp, b"old temporary data").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();

        RuleStore::default().save(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        fs::remove_dir_all(dir).unwrap();
    }
}
