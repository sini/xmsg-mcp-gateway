#[derive(Debug)]
pub struct VerifiedIdentity {
    pub(super) service: String,
    pub(super) issuer: String,
    pub(super) resource: String,
    pub(super) subject: String,
    pub(super) hosted_client: String,
    pub(super) expires_at: u64,
    pub(super) audience: String,
    pub(super) token_family: Option<String>,
    pub(super) admission: Option<(String, i64)>,
    pub(super) admission_policy: Option<crate::outbound::Policy>,
}

impl VerifiedIdentity {
    pub fn token_family(&self) -> Option<&str> {
        self.token_family.as_deref()
    }
    pub(crate) fn admitted_authority(&self) -> Option<crate::grants::Authorization> {
        self.admission
            .as_ref()
            .map(|(id, revision)| crate::grants::Authorization {
                grant_id: id.clone(),
                revision: *revision,
            })
    }
    pub(crate) fn admitted_policy(&self) -> Option<&crate::outbound::Policy> {
        self.admission_policy.as_ref()
    }
    pub fn service(&self) -> &str {
        &self.service
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn hosted_client(&self) -> &str {
        &self.hosted_client
    }
    pub fn same_profile(&self, other: &Self) -> bool {
        self.service == other.service
            && self.issuer == other.issuer
            && self.resource == other.resource
            && self.subject == other.subject
            && self.hosted_client == other.hosted_client
            && self.audience == other.audience
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
