use actix_identity::{Identity, IdentityMiddleware};
use actix_session::SessionMiddleware;
use actix_session::storage::CookieSessionStore;
use actix_web::{get, post, web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web::cookie::Key;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use env_logger::Env;
use log::{debug, info, error};

/// APP STATE
/// For demonstration, we simulate a "user database" in memory.
/// In production, this would be a real database (Postgres, MySQL, etc.).
#[derive(Clone, Debug)]
struct AppState {
    users_db: Arc<Mutex<HashMap<String, String>>>, // username -> password
}

impl AppState {
    fn new() -> Self {
        let users_db = Arc::new(Mutex::new(HashMap::new()));
        // Mock users - in real app, passwords would be hashed
        {
            let mut map = users_db.lock().unwrap();
            map.insert("alice".to_string(), "password123".to_string());
            map.insert("bob".to_string(), "password321".to_string());
        }
        AppState { users_db }
    }

    fn validate_credentials(&self, username: &str, password: &str) -> Option<String> {
        // Checks if received credentials are registered in the user db (is a registered user?)
        // returns username if registered and password is validated, None if not registered 
        let stored_credentials = self.users_db.lock().unwrap();
        if let Some(stored_pass) = stored_credentials.get(username) {
            debug!("user credentials found in the users_database");
            if stored_pass == password {
                debug!("password matched: validated");
                // returning username, in real app, we should probably return user ID from database
                Some(format!("{username}"));
            } else {
                debug!("password does not match");
                return None;
            }
        }
        None  
    }

}

/// STRUCT representing the login request payload.
/// Example: { "username": "alice", "password": "password123" }
#[derive(Deserialize, Debug)]
struct LoginRequest {
    username: String,
    password: String,
}

/// STRUCT representing the http response payload.
/// Example: { "username": "alice", "password": "password123" }
#[derive(Serialize, Debug)]
struct StatusResponse {
    authenticated: bool,
    user_id: String,
    message: String,
}

/// LOGIN
/// - Validates user credentials
/// - If valid, saves the identity in the session (using middleware)
/// - The middleware automatically sets an encrypted cookie on the client
#[post("/login")]
async fn login( 
    creds: web::Json<LoginRequest>,
    user_db: web::Data<AppState>,
    req: HttpRequest
) -> impl Responder {
    info!("Received login request");
    debug!("Login attempt: {:?}", creds);
    debug!("Login attempt [HttpRequest]: {:?}", req);
    // NOTE: In older versions (0.4), id.login("user") worked because login was a method.
	//       In 0.9, the API was redesigned to decouple Identity from the request.
    //       Now you pass &req.extensions() explicitly, and the identity middleware writes the login state there

    // Check if received credential username/password exist and password matches
    if user_db.validate_credentials(&creds.username,&creds.password).is_none() { 
        // Store the user's identity inside the session (via middleware)
        // Under the hood, Actix will set a secure, signed cookie:
        // - SessionMiddleware serializes the session key/value pairs into the cookie
        // - The middleware automatically sets the Set-Cookie header in the HTTP response
        // - The cookie is signed and optionally encrypted using the secret_key
        if Identity::login(&req.extensions(), creds.username.clone()).is_ok() {
            debug!("User [{:?}] logged in", creds.username.to_string() );
            let response = StatusResponse {
                authenticated: true,
                user_id: creds.username.to_string(),
                message: "User is logged in".to_string()
            };
           //return HttpResponse::Ok().body("Login successful");
           return HttpResponse::Ok().json(response);
        } else {
            error!("Login failed: Could not create session");
            return HttpResponse::InternalServerError().body("Login failed: Could not create session");
        }
    }
    let response = StatusResponse {
           authenticated: false,
           user_id: creds.username.to_string(),
           message: "Unauthorized: User not registerd".to_string()
    };
    HttpResponse::Unauthorized().json(response)
   // HttpResponse::Unauthorized().body("Invalid credentials")
}

/// STATUS
/// - Retrieves the current user's identity from the session
/// - If none found, return Unauthorized.
#[get("/status")]
async fn status(identity: Option<Identity>) -> impl Responder {
    debug!("Received status request");
    match identity {
        Some(user) => match user.id() {
            Ok(user_id) => {
                HttpResponse::Ok().json(StatusResponse {
                    authenticated: true,
                    user_id: user_id.clone(),
                    message: format!("User '{}' is authenticated", user_id),
                })
            }
            Err(err) => {
                error!("Failed to read user ID from session: {:?}", err);
                HttpResponse::InternalServerError().json(StatusResponse {
                    authenticated: false,
                    user_id: "".to_string(),
                    message: format!("Session error: {}", err),
                })
            }
        },
        None => {
            error!("No identity found in request (likely no cookie)");
            HttpResponse::Unauthorized().json(StatusResponse {
                authenticated: false,
                user_id: "".to_string(),
                message: "No active session: user is not logged in or session expired".to_string(),
            })
        }
    }
}

/// LOGOUT
/// - Removes the user identity from the session
/// - Actix will clear the corresponding cookie automatically
#[post("/logout")]
async fn logout(identity: Option<Identity>)  -> impl Responder {
    debug!("Received logout request");
    if let Some(user) = identity{
        let response = StatusResponse {
                authenticated: true,
                user_id: user.id().unwrap(),
                message: format!("User {} logged out", user.id().unwrap()),
        };
        Identity::logout(user);
        return HttpResponse::Ok().json(response);
    } 
    let response = StatusResponse {
           authenticated: false,
           user_id: "".to_string(),
           message: "User not logged in".to_string()
    };
    HttpResponse::Unauthorized().json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
     // Set default log level to debug
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    info!("Running Example 2: Session-based authentication with Actix Middlewares");
    
    // Generate a secret key for cookie signing & encryption.
    // In production, this should be a constant value loaded from config or a file
    let secret_key = Key::generate();

    // Create mock user database
    debug!("Creating credentials mock Database");
    let users_state = AppState::new();
    debug!("AppState initialized: user and session DBs...");
    info!("Starting Server at 127.0.0.1 8080...");
    HttpServer::new(move || {
        App::new()
            // state is our AppState: with users database
            .app_data(web::Data::new(users_state.clone()))
            // To start using identity management in your Actix Web application you must register 
            // IdentityMiddleware and SessionMiddleware as middleware on your App.
            // IdentityMiddleware builds on top of SessionMiddleware 
            // The session middleware must be mounted AFTER the identity middleware: `actix-web` invokes middleware in the OPPOSITE
            // order of registration when it receives an incoming request.
            .wrap(IdentityMiddleware::default())
            // SessionMiddleware handles session cookies automatically
            .wrap(SessionMiddleware::new(      // 
                CookieSessionStore::default(), // store sessions in cookies (encrypted) using CookieSessionStore
                secret_key.clone(),            // key for signing/encrypting cookies , generated above
            ))
            // Routes
            .service(login)
            .service(status)
            .service(logout)
            
    })
    .bind(("127.0.0.1", 8080)).expect("Error starting server!")
    .run()
    .await
}