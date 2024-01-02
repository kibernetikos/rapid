use base64::{engine::general_purpose, Engine};
use log::{error, info};
use pqc_dilithium::Keypair;
use repos::{
    session_repo::SessionRepo,
    user_repo::{self, NewUser, User, UserRepo},
};
use serde_json::json;
use service::{AuthError, AuthService};
use std::{fmt::format, sync::Arc};
use worker::*;

mod repos;
mod service;

struct AppContext {
    auth_service: AuthService,
}

struct SharedState {
    user_repo: Arc<UserRepo>,
    session_repo: Arc<SessionRepo>,
}

impl SharedState {
    fn new(user_repo: UserRepo, session_repo: SessionRepo) -> Self {
        Self {
            user_repo: Arc::new(user_repo),
            session_repo: Arc::new(session_repo),
        }
    }
}

#[event(fetch)]
async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    // Handle OPTIONS request for CORS preflight
    if req.method() == Method::Options {
        return Response::empty().map(|resp| resp.with_headers(cors_headers().unwrap()));
    }

    let user_repo = UserRepo::new(&env).map_err(|e| e.to_string())?;
    let session_repo = SessionRepo::new(&env).map_err(|e| e.to_string())?;

    let shared_state = SharedState::new(user_repo, session_repo);

    let keypair = match env
        .kv("auth")
        .expect("KV store access failed")
        .get("keypair")
        .text()
        .await
    {
        // If the keypair is found in the KV store
        Ok(Some(keypair_str)) => {
            // Split the keypair string into its components
            let parts: Vec<&str> = keypair_str.split('#').collect();
            if parts.len() != 2 {
                // Handle the error case where the keypair string does not have exactly two parts
                panic!("Keypair string format is invalid");
            }

            // Decode the parts and reconstruct the keypair
            Keypair::restore(
                general_purpose::STANDARD
                    .decode(parts[0])
                    .expect("Failed to decode public key"),
                general_purpose::STANDARD
                    .decode(parts[1])
                    .expect("Failed to decode secret key"),
            )
        }
        // If the keypair is not found or any error occurs
        _ => {
            // Generate a new keypair
            let keypair = Keypair::generate();

            // Attempt to store the new keypair in the KV store
            let keypair_str = format!(
                "{}#{}",
                general_purpose::STANDARD.encode(keypair.public),
                general_purpose::STANDARD.encode(keypair.expose_secret())
            );

            if let Err(e) = env
                .kv("auth")
                .expect("KV store access failed")
                .put("keypair", &keypair_str)
                .unwrap()
                .execute()
                .await
            {
                // Handle error during keypair storage
                panic!("Failed to store keypair: {:?}", e);
            }

            keypair
        }
    };

    let auth_service = AuthService::new(
        shared_state.user_repo.clone(),
        shared_state.session_repo.clone(),
        keypair,
    );

    let app_context = AppContext { auth_service };

    let router = Router::with_data(app_context);

    let mut response = router
        .post_async("/register", register)
        .post_async("/login", login)
        .get_async("/me", user_info)
        .run(req, env)
        .await?;

    response.headers_mut().set("Access-Control-Allow-Origin", "http://localhost:5173")?;
    response.headers_mut().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    response.headers_mut().set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
    )?;
    response.headers_mut().set("Access-Control-Allow-Credentials", "true")?;

    Ok(response)
}

async fn login(mut req: Request, ctx: RouteContext<AppContext>) -> Result<Response> {
    let auth_service = &ctx.data.auth_service;

    let new_user = match req.json::<NewUser>().await {
        Ok(user) => user,
        Err(_) => return Response::error("Invalid request body", 400),
    };

    match auth_service
        .login(new_user.username, new_user.password)
        .await
    {
        Ok((access_token, refresh_token)) => {
            // JSON response with access token
            let json_response = serde_json::json!({
                "access_token": access_token,
            });

            // Create HTTP-only cookie for the refresh token
            let cookie = format!(
                "refresh_token={}; HttpOnly; Path=/; SameSite=Strict",
                refresh_token
            );

            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            headers.set("Set-Cookie", &cookie)?;

            // Send the JSON response with headers including the Set-Cookie header
            Response::from_json(&json_response).map(|resp| resp.with_headers(headers))
        }
        Err(e) => e.into_worker_error(),
    }
}

async fn register(mut req: Request, ctx: RouteContext<AppContext>) -> Result<Response> {
    let auth_service = &ctx.data.auth_service;

    let new_user = match req.json::<NewUser>().await {
        Ok(user) => user,
        Err(_) => return Response::error("Invalid request body", 400),
    };

    match auth_service
        .register(new_user.username, new_user.password)
        .await
    {
        Ok((access_token, refresh_token)) => {
            // JSON response with access token
            let json_response = serde_json::json!({
                "access_token": access_token,
            });

            // Create HTTP-only cookie for the refresh token
            let cookie = format!(
                "refresh_token={}; HttpOnly; Path=/; SameSite=Strict",
                refresh_token
            );

            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            headers.set("Set-Cookie", &cookie)?;

            // Send the JSON response with headers including the Set-Cookie header
            Response::from_json(&json_response).map(|resp| resp.with_headers(headers))
        }
        Err(e) => e.into_worker_error(),
    }
}

async fn user_info(req: Request, ctx: RouteContext<AppContext>) -> Result<Response> {
    let auth_service = &ctx.data.auth_service;

    // Extract the access token from the request's cookie or Authorization header
    let token = match extract_token(&req) {
        Ok(token) => token,
        Err(e) => return Response::error(e.to_string(), 500),
    };

    // Validate the token and get the claims
    let claims = match auth_service.validate_token(&token) {
        Ok(claims) => claims,
        Err(e) => return e.into_worker_error(),
    };

    console_log!("User info for {} requested", claims.sub);

    // Fetch user data from the user repository
    match auth_service.user_repo.get_by_id(claims.sub).await {
        Ok(user) => {
            let user_data = json!({ "username": user.username, "id": user.id });
            Response::from_json(&user_data)
        }
        Err(_) => Response::error("User not found", 404),
    }
}

fn cors_headers() -> Result<Headers> {
    let mut headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "http://localhost:5173")?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
    )?;
    headers.set("Access-Control-Allow-Credentials", "true")?;
    Ok(headers)
}

// Helper function to extract token from request
fn extract_token(req: &Request) -> std::result::Result<String, worker::Error> {
    // First, try to get the token from the Authorization header
    if let Some(auth_header) = req.headers().get("Authorization").ok().flatten() {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            return Ok(token.trim().to_string());
        }
    }

    // If token is not found in either the Authorization header or cookies, return an error
    Err("Token not found".into())
}
