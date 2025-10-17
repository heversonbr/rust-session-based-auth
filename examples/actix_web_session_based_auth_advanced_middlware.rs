use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{
    get, post, web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_web::cookie::Key;
use actix_web::error::{ErrorUnauthorized, ErrorForbidden};
use env_logger::Env;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use log::{debug, error, info, warn};
use futures::executor::block_on;

// --- SIMULATED ROLES ---
#[derive(Debug, Clone, PartialEq)]
enum Role {
    User,
    Admin,
}

// --- APP STATE: database simulation ---
// Stores (username -> (password_hash, role))
#[derive(Clone, Debug)]
struct AppState {
    users_db: Arc<Mutex<HashMap<String, (String, Role)>>>,
}

impl AppState {
    // WARNING/NOTE: we manually add users and passwrods here in clear text, just for didactial use!
    fn new() -> Self {
        let users_db = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut map = users_db.lock().unwrap();
            // User roles: 'alice' is a standard user, 'bob' is an admin
            map.insert("alice".to_string(), ("password123".to_string(), Role::User));
            map.insert("bob".to_string(), ("password321".to_string(), Role::Admin));
        }
        AppState { users_db }
    }

    // New: Retrieves the user's role from the simulated DB
    fn get_user_role(&self, username: &str) -> Option<Role> {
        let stored_data = self.users_db.lock().unwrap();
        stored_data.get(username).map(|(_, role)| role.clone())
    }

    // Updated: Returns the validated username
    fn validate_credentials(&self, username: &str, password: &str) -> Option<String> {
        // (Simplified sync validation as before for brevity)
        let stored_data = self.users_db.lock().unwrap();
        if let Some((stored_pass, _)) = stored_data.get(username) {
            if stored_pass == password {
                return Some(username.to_string());
            }
        }
        None  
    }
}

// LoginRequest and StatusResponse structs
#[derive(Deserialize, Debug)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize, Debug)]
struct StatusResponse {
    authenticated: bool,
    user_id: String,
    role: String,
    message: String,
}

// Custom Extractors (The Route Guards)
// These two structs implement actix_web::FromRequest to enforce security rules before the handler runs.
// ---
// --- EXTRACTOR 1: AuthUser --- The Base Authentication Extractor
// Purpose: Ensures a user is logged in (authenticated).
// If authentication fails, the request is immediately terminated with a 401 Unauthorized error.
#[derive(Debug)]
struct AuthUser {
    pub user_id: String,
}

impl actix_web::FromRequest for AuthUser {
    type Error = actix_web::Error;
    // Uses the Identity Extractor as a basis
    type Future = futures_util::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
         debug!("FromRequest::from_request() for AuthUser");
        // 1. Try to extract the Identity object placed by IdentityMiddleware
        let identity = Identity::from_request(req, _payload).into_inner();
        
        match identity {
            Ok(id) => match id.id() {
                // 2. Success: Identity found and ID extracted
                Ok(user_id) => {
                    debug!("AuthUser Extractor: User '{}' authenticated.", &user_id);
                    futures_util::future::ok(AuthUser { user_id })
                }
                // 3. Failure: Identity object is corrupted (session error)
                Err(e) => {
                    error!("Session Corrupted: {:?}", e);
                    // Return a 401 Unauthorized error
                    futures_util::future::err(ErrorUnauthorized("Session Error"))
                }
            },
            // 4. Failure: No Identity object found (user is not logged in)
            _ => {
                debug!("AuthUser Extractor: No active identity found.");
                // Return a 401 Unauthorized error
                futures_util::future::err(ErrorUnauthorized("Login Required"))
            }
        }
    }
}

// --- EXTRACTOR 2: AdminUser ---  The Role-Based Access Control Extractor
// Purpose: Ensures a user is logged in AND has the Admin role (Authorization).
// If the role check fails, the request is terminated with a 403 Forbidden error.
#[derive(Debug)]
struct AdminUser {
    pub user_id: String,
}

impl actix_web::FromRequest for AdminUser {
    type Error = actix_web::Error;
    type Future = futures_util::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        dbg!("FromRequest::from_request() for AdminUser");
        // 1. First, reuse the logic of AuthUser to ensure they are logged in.
        let auth_future = AuthUser::from_request(req, payload);
        
        match block_on(auth_future) {
            // 2. Authentication Succeeded: User is logged in. Now check the role.
            Ok(auth_user) => {
                let app_state = req.app_data::<web::Data<AppState>>()
                                    .expect("AppState not found in request data");
                // Check if the user's role is Admin using the AppState
                if let Some(Role::Admin) = app_state.get_user_role(&auth_user.user_id) {
                    debug!("AdminUser Extractor: User '{}' is an Admin.", &auth_user.user_id);
                    // Success: User is both logged in and is an Admin.
                    futures_util::future::ok(AdminUser { user_id: auth_user.user_id })
                } else {
                    debug!("AdminUser Extractor: User '{}' lacks Admin role.", &auth_user.user_id);
                    // Failure: User is logged in but lacks the role. Send 403 Forbidden.
                    futures_util::future::err(ErrorForbidden("Admin Access Required"))
                }
            }
            // 3. Authentication Failed: Error from AuthUser (likely 401 Unauthorized)
            Err(e) => {
                // Pass the authentication error up (e.g., the 401 from AuthUser)
                futures_util::future::err(e)
            }
        }
    }
}

// Routes (Handler Implementation)
// Now, the security logic is entirely moved to the Extractor arguments, 
// making the handlers clean and focused on business logic.
// ------------------------
// --- PROTECTED ROUTES ---
// ------------------------
// /profile route: Requires *any* logged-in user (AuthUser)
// The handler only runs if the AuthUser extraction succeeds (i.e., user is authenticated).
#[get("/profile")]
async fn profile(user: AuthUser, app_state: web::Data<AppState>) -> impl Responder {
    dbg!("/profile route");
    let role = app_state.get_user_role(&user.user_id).map(|r| format!("{:?}", r)).unwrap_or_else(|| "Unknown".to_string());
    
    info!("Access Granted: /profile for User: {}", user.user_id);
    HttpResponse::Ok().json(StatusResponse {
        authenticated: true,
        user_id: user.user_id,
        role,
        message: "Welcome to your profile area!".to_string(),
    })
}

// /admin route: Requires an Admin user (AdminUser)
// The handler only runs if the AdminUser extraction succeeds (i.e., user is authenticated AND admin).
#[get("/admin")]
async fn admin_dashboard(admin: AdminUser) -> impl Responder {
    dbg!("/admin_dashboard route");
    info!("Access Granted: /admin for Admin: {}", admin.user_id);
    HttpResponse::Ok().json(StatusResponse {
        authenticated: true,
        user_id: admin.user_id,
        role: "Admin".to_string(),
        message: "Welcome to the restricted Admin Dashboard!".to_string(),
    })
}

// --------------------------
// --- UNPROTECTED ROUTES ---
// --------------------------
// index route
#[get("/")]
async fn index() -> impl Responder {
    dbg!("/index public route");
    HttpResponse::Ok().body("Welcome to the public homepage.")
}

// /login route: handles session creation)
#[post("/login")]
async fn login( 
    creds: web::Json<LoginRequest>,
    user_db: web::Data<AppState>,
    req: HttpRequest
) -> impl Responder {
    dbg!("/login route");
    // ... (Login logic to validate credentials and call Identity::login) ...
    if let Some(user_id) = user_db.validate_credentials(&creds.username,&creds.password) {
        if Identity::login(&req.extensions(), user_id.clone()).is_ok() {
            let role = user_db.get_user_role(&user_id).map(|r| format!("{:?}", r)).unwrap_or_default();
            let response = StatusResponse {
                authenticated: true,
                user_id,
                role,
                message: "Login successful".to_string()
            };
           return HttpResponse::Ok().json(response);
        } else {
            error!("Login failed: Could not create session");
            return HttpResponse::InternalServerError().body("Login failed: Could not create session");
        }
    }
    
    // Invalid credentials path
    HttpResponse::Unauthorized().json(StatusResponse {
           authenticated: false,
           user_id: creds.username.to_string(), 
           role: "".to_string(),
           message: "Unauthorized: Invalid credentials or user not found".to_string()
    })
}

// /logout route: handles logout and clears sessions
// Clears the session identity.
// Does not require the AuthUser extractor because it needs to handle the case 
// where the user attempts to log out but is already logged out.
// In other words, use the Option<Identity> extractor for the /logout route, 
// which must be robust enough to handle the non-authenticated case gracefully.
#[post("/logout")]
async fn logout(identity: Option<Identity>) -> impl Responder {
    debug!("Received logout request");
    
    if let Some(user_id) = identity.as_ref().and_then(|id| id.id().ok()) {
        // User was logged in. Clear the identity. This tells IdentityMiddleware to remove the session cookie.
        info!("User {} logged out successfully.", user_id);
        Identity::logout(identity.unwrap());
        
        HttpResponse::Ok().json(StatusResponse {
            authenticated: false,
            user_id: user_id.clone(),
            role: "".to_string(),
            message: format!("User {} logged out.", user_id),
        })
    } else {
        // No active identity found (already logged out or session expired)
        warn!("Logout attempt: No active session to clear.");
        HttpResponse::Unauthorized().json(StatusResponse {
           authenticated: false,
           user_id: "".to_string(),
           role: "".to_string(),
           message: "User was not logged in.".to_string()
        })
    }
}


// main function
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    info!("Running Didactical Example: Role-Based Access Control");
    info!("Starting server at http://127.0.0.1:8080");
    let secret_key = Key::generate();
    let users_state = AppState::new();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(users_state.clone()))
            // MIDDLEWARE LAYER (Prepares the request for the extractors)
            .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
            // ROUTE LAYER (The Extractors enforce security here)
            .service(index)           // Public Route (200)
            .service(login)           // Public Route (creates session 200)
            .service(logout)          // Public Route (removes session 200)
            .service(profile)         // Protected (AuthUser enforces 401)
            .service(admin_dashboard) // Protected (AdminUser enforces 401/403)
            
    })
    .bind(("127.0.0.1", 8080)).expect("Error starting server!")
    .run()
    .await
}