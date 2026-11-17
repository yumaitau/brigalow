use super::*;

/// RFC 7636 S256 code challenge: BASE64URL-NOPAD(SHA-256(ASCII(verifier))).
fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Authorization-code request parameters set by Brigalow. A configured
/// authorization URL must not pre-set any of them.
const AUTHORIZE_PARAMS: [&str; 8] = [
    "response_type",
    "client_id",
    "state",
    "code_challenge",
    "code_challenge_method",
    "redirect_uri",
    "scope",
    "nonce",
];

fn authorize_url(
    authorization_url: &str,
    client_id: &str,
    redirect: &str,
    state: &str,
    challenge: &str,
    nonce: &str,
) -> Result<url::Url, AuthError> {
    url::Url::parse(redirect).map_err(|_| AuthError)?;
    let mut url = url::Url::parse(authorization_url).map_err(|_| AuthError)?;
    if url.cannot_be_a_base()
        || url
            .query_pairs()
            .any(|(k, _)| AUTHORIZE_PARAMS.contains(&k.as_ref()))
    {
        return Err(AuthError);
    }
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("redirect_uri", redirect)
        .append_pair("scope", "openid groups")
        .append_pair("nonce", nonce);
    Ok(url)
}
pub(super) struct Pending {
    org: Uuid,
    provider: String,
    browser_hash: String,
    nonce: String,
    pkce: String,
    expires: Instant,
}
pub struct Login {
    pub url: String,
    pub browser: String,
}
impl Identity {
    fn redirect(&self, a: &Authority) -> String {
        format!(
            "{}/auth/{}/{}/callback",
            self.config.public_url.trim_end_matches('/'),
            a.org_id,
            a.name
        )
    }
    pub async fn login(&self, org: Uuid, provider: &str) -> Result<Login, AuthError> {
        let a = self.authority(org, provider)?;
        let h = a.human.as_ref().ok_or(AuthError)?;
        let pkce = random_secret();
        let nonce = random_secret();
        let state = random_secret();
        let url = authorize_url(
            &h.authorization_url,
            &h.client_id,
            &self.redirect(a),
            &state,
            &pkce_s256(&pkce),
            &nonce,
        )?;
        let browser = random_secret();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, p| p.expires > Instant::now());
        if pending.len() >= 1024 {
            return Err(AuthError);
        }
        pending.insert(
            hash(&state),
            Pending {
                org,
                provider: provider.into(),
                browser_hash: hash(&browser),
                nonce,
                pkce,
                expires: Instant::now() + Duration::from_secs(300),
            },
        );
        Ok(Login {
            url: url.into(),
            browser,
        })
    }
    pub async fn complete(
        &self,
        org: Uuid,
        provider: &str,
        state: &str,
        code: &str,
        browser: &str,
    ) -> Result<(Principal, i64), AuthError> {
        use subtle::ConstantTimeEq;
        if state.len() > 256 || code.len() > 4096 || browser.len() > 256 {
            return Err(AuthError);
        }
        let mut pending = self.pending.lock().await;
        let key = hash(state);
        let p = pending.get(&key).ok_or(AuthError)?;
        if p.org != org
            || p.provider != provider
            || p.expires <= Instant::now()
            || !bool::from(p.browser_hash.as_bytes().ct_eq(hash(browser).as_bytes()))
        {
            return Err(AuthError);
        }
        let p = pending.remove(&key).ok_or(AuthError)?;
        drop(pending);
        let a = self.authority(org, provider)?;
        let h = a.human.as_ref().ok_or(AuthError)?;
        let response = self
            .http
            .post(&h.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", h.client_id.as_str()),
                ("redirect_uri", self.redirect(a).as_str()),
                ("code_verifier", p.pkce.as_str()),
            ])
            .send()
            .await
            .map_err(|_| AuthError)?;
        let response = Self::json_response(response).await?;
        let token = response["id_token"].as_str().ok_or(AuthError)?;
        let (claims, _) = self.verified(a, token, &h.client_id).await?;
        validate_id_claims(&claims, &h.client_id, &p.nonce, now())?;
        let groups = claims["groups"].as_array().ok_or(AuthError)?;
        let mut roles = Vec::new();
        for group in groups {
            if let Some(role) = group.as_str().and_then(|g| h.group_roles.get(g)) {
                if !roles.contains(role) {
                    roles.push(*role);
                }
            }
        }
        if roles.is_empty() {
            return Err(AuthError);
        }
        Ok((
            Self::principal(a, &claims, roles, None, true)?,
            claims["exp"].as_i64().ok_or(AuthError)?.min(now() + 3600),
        ))
    }
}

/// Narrow OIDC authorization-code profile, after JWT signature/issuer/time validation.
/// As before, additional audiences are untrusted; implicit/hybrid flows are unsupported.
fn validate_id_claims(
    claims: &serde_json::Value,
    client: &str,
    expected_nonce: &str,
    now: i64,
) -> Result<(), AuthError> {
    use subtle::ConstantTimeEq;
    let audience = match &claims["aud"] {
        serde_json::Value::String(aud) => aud == client,
        serde_json::Value::Array(aud) => aud.len() == 1 && aud[0].as_str() == Some(client),
        _ => false,
    };
    let nonce = claims["nonce"].as_str().ok_or(AuthError)?;
    let issued = claims["iat"].as_i64().ok_or(AuthError)?;
    let expires = claims["exp"].as_i64().ok_or(AuthError)?;
    if !audience
        || claims
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(client))
        || issued < 0
        || issued > now + 30
        || issued >= expires
        || !bool::from(
            hash(nonce)
                .as_bytes()
                .ct_eq(hash(expected_nonce).as_bytes()),
        )
    {
        return Err(AuthError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc7636_appendix_b() {
        assert_eq!(
            pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn authorize_url_sets_code_flow_parameters_once() {
        let url = authorize_url(
            "https://idp.test/authorize?tenant=a",
            "client",
            "https://brigalow.test/auth/x/y/callback",
            "st",
            "ch",
            "no",
        )
        .unwrap();
        let q: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let get = |k: &str| {
            let v: Vec<_> = q.iter().filter(|(n, _)| n == k).collect();
            assert_eq!(v.len(), 1, "{k}");
            v[0].1.clone()
        };
        assert_eq!(get("tenant"), "a");
        assert_eq!(get("response_type"), "code");
        assert_eq!(get("client_id"), "client");
        assert_eq!(get("state"), "st");
        assert_eq!(get("code_challenge"), "ch");
        assert_eq!(get("code_challenge_method"), "S256");
        assert_eq!(
            get("redirect_uri"),
            "https://brigalow.test/auth/x/y/callback"
        );
        assert_eq!(get("scope"), "openid groups");
        assert_eq!(get("nonce"), "no");
    }

    #[test]
    fn authorize_url_rejects_reserved_or_invalid_urls() {
        let redirect = "https://brigalow.test/cb";
        for bad in [
            "https://idp.test/authorize?state=fixed",
            "https://idp.test/authorize?code_challenge_method=plain",
            "https://idp.test/authorize?nonce=x",
            "not a url",
            "mailto:idp@test",
        ] {
            assert!(
                authorize_url(bad, "c", redirect, "s", "ch", "n").is_err(),
                "{bad}"
            );
        }
        assert!(authorize_url("https://idp.test/a", "c", "relative", "s", "ch", "n").is_err());
    }
}
