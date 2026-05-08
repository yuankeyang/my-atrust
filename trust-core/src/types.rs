//! Common types for ATrust

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserId(pub Uuid);
