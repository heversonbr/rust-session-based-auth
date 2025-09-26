use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use env_logger::Env;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use uuid::Uuid;
use log::{debug, info, error};

/// Shared app state that provides:
/// - `users`: fake user database (username → password)
/// - `sessions`: server-side session database (session_id → username)
#[derive(Clone)]
struct AppState {
    users: Arc<Mutex<HashMap<String, String>>>,
    sessions: Arc<Mutex<HashMap<String, String>>>,
}

/// Login request payload: a json object with { "username": "...", "password": "..." }
/// used to send credentials to login 
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// LOGIN 
/// 1. Verify credentials against fake DB.
/// 2. If valid, generate a random session_id (UUID).
/// 3. Store it in the server-side sessions HashMap.
/// 4. Return session_id back to the client in a cookie (`Set-Cookie` header).
#[post("/login")]
async fn login(data: web::Data<AppState>, creds: web::Json<LoginRequest>) -> impl Responder {
    debug!("Received login request");
    let users = data.users.lock().unwrap();
    debug!("Checking credentials");
    if let Some(stored_pw) = users.get(&creds.username) {
        debug!("Found user, checking password...");
        // Verify password in user's database
        if stored_pw == &creds.password {
            debug!("Password validated");
            // Generate session ID, if verified ok
            let session_id = Uuid::new_v4().to_string();
            debug!("Generated session ID: {:?}" , &session_id);
            // Save mapping session_id -> username in our fake Session store 
            let mut sessions = data.sessions.lock().unwrap();
            sessions.insert(session_id.clone(), creds.username.clone());
            debug!("Inserting session id: {:?} and corresponding user: {:?} into our fake Session store", &session_id, &creds.username);
            // Build response with a Set-Cookie header
            let cookie_header = format!("session_id={}; HttpOnly; Path=/", session_id);
            debug!("Returning HttpResponse with cookie: {:?}", &cookie_header);
            return HttpResponse::Ok()
                .insert_header(("Set-Cookie", cookie_header))
                .body("Login successful");
        }
    }
     error!("Invalid credentials");
    HttpResponse::Unauthorized().body("Invalid credentials")
}

/// STATUS
/// 1. Read `session_id` cookie from request `Cookie` header.
/// 2. Look up session_id in sessions DB.
/// 3. If found, return username.
#[get("/status")]
async fn status(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Received status request");
    if let Some(cookie_header) = req.headers().get("Cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            debug!("Received Cookie header: {:?} ", cookie_str);
            // Find "session_id" in raw cookie string
            for pair in cookie_str.split(';') {
                let trimmed = pair.trim();
                if let Some(value) = trimmed.strip_prefix("session_id=") {
                    let sessions = data.sessions.lock().unwrap();
                    debug!("Checking user {:?} in our fake user DB", &value);
                    if let Some(username) = sessions.get(value) {
                         debug!("User {:?} is logged. Returning Ok", &username);
                        return HttpResponse::Ok()
                            .body(format!("You are logged in as {username}"));
                    }
                }
            }
        }
    }
    error!("User Not logged in");
    HttpResponse::Unauthorized().body("Not logged in")
}

/// LOGOUT
/// 1. Read `session_id` from `Cookie` header.
/// 2. Remove `session_id` from sessions DB.
/// 3. Clear cookie in response: Send back a `Set-Cookie` that expires the cookie.
#[get("/logout")]
async fn logout(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    debug!("Received logout request");
    if let Some(cookie_header) = req.headers().get("Cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            debug!("Received Cookie header: {:?} ", cookie_str);
            for pair in cookie_str.split(';') {
                let trimmed = pair.trim();
                if let Some(value) = trimmed.strip_prefix("session_id=") {
                    // Remove session from DB
                    let mut sessions = data.sessions.lock().unwrap();
                    debug!("Removing session {:?} from session store", &value);
                    sessions.remove(value);
                    // Expire cookie manually
                    let expired_cookie =
                        "session_id=; HttpOnly; Path=/; Max-Age=0".to_string();
                    debug!("Returning Cookie to clear session in the client side: {:?}", &expired_cookie);
                    return HttpResponse::Ok()
                        .insert_header(("Set-Cookie", expired_cookie))
                        .body("Logged out");
                }
            }
        }
    }
    error!("User Not logged in");
    HttpResponse::Unauthorized().body("Not logged in")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Set default log level to debug
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();    
    debug!("Running Example 1: Minimal session-based authentication");

     // Create our Fake user DB
    let mut fake_users = HashMap::new();
    debug!("Creating credentials mock Database for users alice and bob...");
    fake_users.insert("alice".to_string(), "password123".to_string());
    fake_users.insert("bob".to_string(), "password321".to_string());

    // Initialize app state with both user DB and sessions id DB
    let appstate = AppState {
        users: Arc::new(Mutex::new(fake_users)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    debug!("AppState initialized: user and session DBs...");
    info!("Starting Server at 127.0.0.1 8080...");
    HttpServer::new(move || {
        App::new()
            // App state (our databases)
            .app_data(web::Data::new(appstate.clone()))
            // Routes
            .service(login)
            .service(status)
            .service(logout)
    })
    .bind(("127.0.0.1", 8080)).expect("Error starting server!")
    .run()
    .await
}