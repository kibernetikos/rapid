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
    let keypair = Keypair::generate();

    let auth_service = AuthService::new(
        shared_state.user_repo.clone(),
        shared_state.session_repo.clone(),
        keypair,
    );

    let app_context = AppContext { auth_service };

    let router = Router::with_data(app_context);

    let response = router
        .post_async("/register", register)
        .post_async("/login", login)
        .get_async("/me", user_info)
        .run(req, env)
        .await?;

    // Apply CORS headers to the response
    Ok(response.with_headers(cors_headers().unwrap()))
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
            let tokens = serde_json::json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
            });

            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;

            Response::from_json(&tokens).map(|resp| resp.with_headers(headers))
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
            let tokens = serde_json::json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
            });

            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;

            Response::from_json(&tokens).map(|resp| resp.with_headers(headers))
        }
        Err(e) => e.into_worker_error(),
    }
}

async fn user_info(req: Request, ctx: RouteContext<AppContext>) -> Result<Response> {
    let auth_service = &ctx.data.auth_service;

    // Extract the access token from the request's cookie or Authorization header
    let token = extract_token(&req)?;

    // Validate the token and get the claims
    let claims = match auth_service.validate_token(&token) {
        Ok(claims) => claims,
        Err(e) => return e.into_worker_error(),
    };

    info!("User info for {} requested", claims.sub);

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
fn extract_token(req: &Request) -> std::result::Result<(String), worker::Error> {
    // If not found in the Authorization header, try to get it from the cookies
    if let Some(cookie_header) = req.headers().get("Cookie").ok().flatten() {
        for cookie in cookie_header.split(';') {
            let parts: Vec<&str> = cookie.split('=').collect();
            if parts.len() == 2 && parts[0].trim() == "access_token" {
                return Ok(parts[1].trim().to_string());
            }
        }
    }

    // If token is not found in either, return an error response
    Err("Token not found".into())
}
