use super::*;

fn claim_matches(value: Option<&serde_json::Value>, expected: &str) -> bool {
    match value {
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Bool(b)) => (if *b { "true" } else { "false" }) == expected,
        _ => false,
    }
}

fn rule_matches(rule: &WorkloadRule, claims: &serde_json::Value) -> bool {
    rule.claims
        .iter()
        .all(|(k, v)| claim_matches(claims.get(k), v))
}

impl Identity {
    /// Diagnostic only: reverify before naming a failed configured claim in the audit log.
    pub async fn rejected_claim(
        &self,
        org: Uuid,
        token: &str,
        scope: &Scope,
    ) -> Option<(String, String)> {
        for a in self
            .config
            .authorities
            .iter()
            .filter(|a| a.org_id == org && !a.workloads.is_empty())
        {
            let Ok((claims, _)) = self.verified(a, token, &format!("brigalow:{org}")).await else {
                continue;
            };
            let rule = a
                .workloads
                .iter()
                .find(|r| r.project == scope.project && r.policy == scope.policy)?;
            let (name, _) = rule
                .claims
                .iter()
                .find(|(k, v)| !claim_matches(claims.get(*k), v))?;
            let p = Self::principal(a, &claims, vec![], None, false).ok()?;
            return Some((p.actor, name.clone()));
        }
        None
    }
    pub async fn workload(
        &self,
        org: Uuid,
        token: &str,
        scope: &Scope,
    ) -> Result<Principal, AuthError> {
        let principal = self.verify_workload(org, token, Some(scope)).await?;
        if !principal.permits_scope(scope.project, Some(scope.policy)) {
            return Err(AuthError);
        }
        Ok(principal)
    }
    pub async fn verify_workload(
        &self,
        org: Uuid,
        token: &str,
        scope: Option<&Scope>,
    ) -> Result<Principal, AuthError> {
        if token.len() > 16384 {
            return Err(AuthError);
        }
        // Unverified issuer only selects from pinned configuration; it never selects a network URL.
        let raw = token.split('.').nth(1).ok_or(AuthError)?;
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(raw).map_err(|_| AuthError)?)
                .map_err(|_| AuthError)?;
        let issuer = claims["iss"].as_str().ok_or(AuthError)?;
        let a = self
            .config
            .authorities
            .iter()
            .find(|a| a.org_id == org && a.issuer == issuer && !a.workloads.is_empty())
            .ok_or(AuthError)?;
        let (claims, _) = self.verified(a, token, &format!("brigalow:{org}")).await?;
        // CI identity must be short-lived; an exp-only, arbitrarily long token is insufficient.
        let issued = claims["iat"].as_i64().ok_or(AuthError)?;
        let expires = claims["exp"].as_i64().ok_or(AuthError)?;
        let lifetime = expires.checked_sub(issued).ok_or(AuthError)?;
        if issued < 0 || issued > now() + 30 || !(1..=3600).contains(&lifetime) {
            return Err(AuthError);
        }
        // Prefer the rule matching the target scope; fall back to any matching rule so
        // callers return a uniform 404 via permits_scope rather than leaking existence via 401.
        let rule = scope
            .and_then(|scope| {
                a.workloads.iter().find(|r| {
                    r.project == scope.project
                        && r.policy == scope.policy
                        && rule_matches(r, &claims)
                })
            })
            .or_else(|| a.workloads.iter().find(|r| rule_matches(r, &claims)))
            .ok_or(AuthError)?;
        Self::principal(
            a,
            &claims,
            vec![Role::Submitter],
            Some(Scope {
                project: rule.project,
                policy: rule.policy,
            }),
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_claim_matching_accepts_strings_and_booleans() {
        assert!(claim_matches(
            Some(&serde_json::json!("acme/app")),
            "acme/app"
        ));
        assert!(claim_matches(Some(&serde_json::json!(true)), "true"));
        assert!(claim_matches(Some(&serde_json::json!(false)), "false"));
        assert!(!claim_matches(Some(&serde_json::json!(false)), "true"));
        assert!(!claim_matches(Some(&serde_json::json!(1)), "1"));
        assert!(!claim_matches(None, "true"));
    }

    #[test]
    fn identity_rejects_public_url_with_query_or_path() {
        for bad in [
            "https://brigalow.test/?x=1",
            "https://brigalow.test/prefix",
            "http://brigalow.test",
        ] {
            assert!(Identity::new(
                IdentityConfig {
                    public_url: bad.into(),
                    ca_file: None,
                    authorities: vec![],
                },
                Mode::Lab
            )
            .is_err());
        }
    }
}
