use std::error::Error;
use uuid::Uuid;
use worker::{D1Database, Env, Date};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid, // Unique identifier for the session
    pub user_id: Uuid, // Associated user ID
    pub token: String, // Token or token identifier
    pub created_at: u64, // Timestamp for session creation
    pub expires_at: u64, // Timestamp for session expiration
}

pub struct SessionRepo {
    d1: D1Database,
}

impl SessionRepo {
    pub fn new(env: &Env) -> Result<Self, Box<dyn Error>> {
        let d1 = env.d1("DB")?;
        Ok(SessionRepo { d1 })
    }

    pub async fn create_session(
        &self,
        user_id: Uuid,
        token: String,
        expires_at: u64,
    ) -> Result<Session, Box<dyn std::error::Error>> {
        let session_id = Uuid::new_v4();
        let created_at = Date::now().as_millis() / 1000;
        let expires_at = (Date::now().as_millis() / 1000) + expires_at;

        self.d1
            .prepare("INSERT INTO session (id, user_id, token, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)")
            .bind(&[
                session_id.to_string().into(),
                user_id.to_string().into(),
                token.clone().into(),
                (created_at as i32).into(),
                (expires_at as i32).into(),
            ])?
            .run()
            .await?;

        Ok(Session {
            id: session_id,
            user_id,
            token,
            created_at,
            expires_at,
        })
    }

    pub async fn invalidate_session(
        &self,
        session_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.d1
            .prepare("DELETE FROM session WHERE id = ?1")
            .bind(&[session_id.to_string().into()])?
            .run()
            .await?;

        Ok(())
    }

    pub async fn get_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<Session>, Box<dyn std::error::Error>> {
        let query = self.d1
            .prepare("SELECT * FROM session WHERE id = ?1")
            .bind(&[session_id.to_string().into()])?;

        let result: Option<Session> = query.first(None).await?;
        Ok(result)
    }

    pub async fn is_session_valid(
        &self,
        session_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(session) = self.get_session(session_id).await? {
            let current_timestamp = Date::now().as_millis() / 1000;
            Ok(session.expires_at > current_timestamp)
        } else {
            Ok(false)
        }
    }

    pub async fn invalidate_all_sessions_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.d1
            .prepare("DELETE FROM session WHERE user_id = ?1")
            .bind(&[user_id.to_string().into()])?
            .run()
            .await?;

        Ok(())
    }
}
