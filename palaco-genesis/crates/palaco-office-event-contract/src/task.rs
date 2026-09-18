#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// Canonical payload for Microsoft To Do task creation.
pub struct TaskCreatePayload {
    /// Explicit To Do list identifier.
    pub list_id: String,
    /// Task title.
    pub title: String,
    /// Optional task body.
    pub body: Option<String>,
}

impl TaskCreatePayload {
    /// Validates resource binding and required task content.
    pub fn validate(&self) -> Result<(), String> {
        if self.list_id.trim().is_empty() { return Err("list_id is required".into()); }
        if self.title.trim().is_empty() { return Err("title is required".into()); }
        Ok(())
    }

    /// Returns the canonical JSON representation after validation.
    pub fn canonical_json(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| error.to_string())
    }
}
