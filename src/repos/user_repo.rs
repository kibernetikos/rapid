use std::error::Error;

use bcrypt::hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, Env, Date};

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password: String,
}

pub struct UserRepo {
    d1: D1Database,
}

impl UserRepo {
    pub fn new(env: &Env) -> Result<Self, Box<dyn Error>> {
        let d1 = env.d1("DB")?;
        Ok(UserRepo { d1 })
    }

    pub async fn create(
        &self,
        username: String,
        password: String,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let hashed_password = hash(password, bcrypt::DEFAULT_COST)?;
        let user_id = Uuid::new_v4();
        let created_at = Date::now().as_millis() / 1000;
        self.d1
            .prepare("INSERT INTO user (id, username, password, created_at) VALUES (?1, ?2, ?3, ?4)")
            .bind(&[
                user_id.to_string().into(),
                username.clone().into(),
                hashed_password.clone().into(),
                (created_at as i32).into(),
            ])?
            .run()
            .await?;

        Ok(User {
            id: user_id,
            username,
            password: hashed_password,
            created_at,
        })
    }

    pub async fn get_by_id(
        &self,
        id: Uuid,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let q = self
            .d1
            .prepare("SELECT * FROM user WHERE id = ?1 LIMIT 1")
            .bind(&[id.to_string().into()])?;
    
        let result: Option<User> = q.first(None).await?;
    
        match result {
            Some(user) => Ok(user),
            None => Err("User not found".into()), // Return an error if no user is found
        }
    }

    pub async fn get_by_username(
        &self,
        username: String,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let q = self
            .d1
            .prepare("SELECT * FROM user WHERE username = ?1 LIMIT 1")
            .bind(&[username.into()])?;
    
        let result: Option<User> = q.first(None).await?;
    
        match result {
            Some(user) => Ok(user),
            None => Err("User not found".into()), // Return an error if no user is found
        }
    }
}
