import os
from urllib import request

from dotenv import load_dotenv
from supabase import create_client
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from password_utils import hash_password, verify_password

from kerberos.kerberos import (
    AuthenticationServer,
    TicketGrantingServer,
    ServiceServer
)





from kerberos.crypto_utils import (
    generate_key,
    encrypt,
    decrypt,
    derive_key_from_password
)

from datetime import datetime




class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str

class ServiceRequest(BaseModel):
    username: str
    service_name: str

class AccessRequest(BaseModel):
    username: str
    service_name: str
    service_ticket: str

class ServiceCreateRequest(BaseModel):
    service_name: str


class PermissionRequest(BaseModel):
    username: str
    service_name: str



load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Create the Authentication Server
tgs_key = generate_key()
as_server = AuthenticationServer(tgs_key)

service_key = generate_key()

tgs_server = TicketGrantingServer(
    tgs_key,
    service_key
)


service_server = ServiceServer(service_key)

kerberos_sessions = {}


@app.get("/")
def root():
    return {
        "message": "Kerberos Q2 Backend is running!"
    }


@app.get("/test-kerberos")
def test_kerberos():
    return {
        "message": "Kerberos module connected successfully!"
    }
@app.get("/test-supabase")
def test_supabase():
    response = supabase.table("services").select("*").execute()

    return {
        "message": "Supabase connection successful!",
        "services": response.data
    }

@app.post("/register")
def register_user(request: RegisterRequest):

    password_hash = hash_password(request.password)

    response = (
        supabase
        .table("users")
        .insert({
            "username": request.username,
            "password_hash": password_hash
        })
        .execute()
    )

    return {
        "message": "User registered successfully!",
        "username": request.username
    }

@app.get("/users")
def get_users():
    response = (
        supabase
        .table("users")
        .select("id, username, created_at")
        .execute()
    )

    return {
        "users": response.data
    }

@app.post("/login")
def login_user(request: LoginRequest):

    # Find user in database
    response = (
        supabase
        .table("users")
        .select("*")
        .eq("username", request.username)
        .execute()
    )

    if not response.data:
        return {
            "success": False,
            "message": "User not found"
        }

    user = response.data[0]

    # Verify password
    if not verify_password(
        request.password,
        user["password_hash"]
    ):
        return {
            "success": False,
            "message": "Invalid password"
        }

    # Start Kerberos authentication
    try:
        kerberos_response = as_server.authenticate_client(
            request.username,
            request.password
        )

       

        client_key = derive_key_from_password(
    request.password,
    request.username.encode("utf-8")
    )

        client_data = decrypt(
    kerberos_response,
    client_key
        )

        client_tgs_key_hex, encrypted_tgt = client_data.split("|")

        kerberos_sessions[request.username] = {
            "client_tgs_key": client_tgs_key_hex,
            "encrypted_tgt": encrypted_tgt
        }

        return {
            "success": True,
            "message": "Kerberos authentication successful!",
            "username": request.username,
            "kerberos_data": kerberos_response
        }

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

@app.post("/request-service-ticket")
def request_service_ticket(request: ServiceRequest):

    # Check whether the user has logged in
    if request.username not in kerberos_sessions:
        return {
            "success": False,
            "message": "User is not logged in"
        }

    session = kerberos_sessions[request.username]

    try:
        # Get Kerberos session information
        client_tgs_key = bytes.fromhex(
            session["client_tgs_key"]
        )

        encrypted_tgt = session["encrypted_tgt"]

        # Create authenticator
        from datetime import datetime

        authenticator_data = (
            f"{request.username}|"
            f"{datetime.now().isoformat()}"
        )

        encrypted_authenticator = encrypt(
            authenticator_data,
            client_tgs_key
        )

        # Ask TGS for a service ticket
        tgs_response = tgs_server.issue_service_ticket(
            encrypted_tgt,
            request.service_name,
            encrypted_authenticator
        )

        client_service_key_hex, encrypted_service_ticket = (
            tgs_response.split("|")
        )

        kerberos_sessions[request.username]["client_service_key"] = (
    client_service_key_hex
)

        return {
            "success": True,
            "message": "Service ticket generated successfully!",
            "username": request.username,
            "service_name": request.service_name,
            "service_ticket": encrypted_service_ticket
        }

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

def check_permission(username: str, service_name: str):

    # Get user ID
    user_response = (
        supabase
        .table("users")
        .select("id")
        .eq("username", username)
        .execute()
    )

    if not user_response.data:
        return False

    user_id = user_response.data[0]["id"]

    # Get service ID
    service_response = (
        supabase
        .table("services")
        .select("id")
        .eq("service_name", service_name)
        .execute()
    )

    if not service_response.data:
        return False

    service_id = service_response.data[0]["id"]

    # Check permission
    permission_response = (
        supabase
        .table("permissions")
        .select("id")
        .eq("user_id", user_id)
        .eq("service_id", service_id)
        .execute()
    )

    return bool(permission_response.data)

@app.post("/access-service")
def access_service(request: AccessRequest):

    if request.username not in kerberos_sessions:
        return {
            "success": False,
            "message": "User is not logged in"
        }

    session = kerberos_sessions[request.username]

    try:
        client_service_key = bytes.fromhex(
            session["client_service_key"]
        )

        # Create a new authenticator for the service server
        from datetime import datetime

        authenticator_data = (
            f"{request.username}|"
            f"{datetime.now().isoformat()}"
        )

        encrypted_authenticator = encrypt(
            authenticator_data,
            client_service_key
        )

        # Service Server verifies the ticket
        service_server.authenticate_client(
    request.service_ticket,
    encrypted_authenticator)

# Check authorization
        has_permission = check_permission(
    request.username,
    request.service_name
)

        if not has_permission:
            return {
        "success": False,
        "message": "Access denied",
        "username": request.username,
        "service_name": request.service_name
    }

        return {
    "success": True,
    "message": "Access granted",
    "username": request.username,
    "service_name": request.service_name
}

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

@app.get("/services")
def get_services():
    response = supabase.table("services").select("*").order("service_name").execute()

    return {
        "success": True,
        "services": response.data
    }


@app.post("/services")
def add_service(request: ServiceCreateRequest):
    service_name = request.service_name.strip()

    if not service_name:
        return {
            "success": False,
            "message": "Service name cannot be empty"
        }

    # Check whether service already exists
    existing = (
        supabase
        .table("services")
        .select("id, service_name")
        .eq("service_name", service_name)
        .execute()
    )

    if existing.data:
        return {
            "success": False,
            "message": "Service already exists"
        }

    response = (
        supabase
        .table("services")
        .insert({
            "service_name": service_name
        })
        .execute()
    )

    return {
        "success": True,
        "message": f"Service '{service_name}' added successfully",
        "service": response.data[0]
    }


@app.post("/permissions")
def add_permission(request: PermissionRequest):
    # Find user
    user_response = (
        supabase
        .table("users")
        .select("id, username")
        .eq("username", request.username)
        .execute()
    )

    if not user_response.data:
        return {
            "success": False,
            "message": f"User '{request.username}' not found"
        }

    # Find service
    service_response = (
        supabase
        .table("services")
        .select("id, service_name")
        .eq("service_name", request.service_name)
        .execute()
    )

    if not service_response.data:
        return {
            "success": False,
            "message": f"Service '{request.service_name}' not found"
        }

    user_id = user_response.data[0]["id"]
    service_id = service_response.data[0]["id"]

    # Check existing permission
    existing = (
        supabase
        .table("permissions")
        .select("id")
        .eq("user_id", user_id)
        .eq("service_id", service_id)
        .execute()
    )

    if existing.data:
        return {
            "success": False,
            "message": "Permission already exists"
        }

    response = (
        supabase
        .table("permissions")
        .insert({
            "user_id": user_id,
            "service_id": service_id
        })
        .execute()
    )

    return {
        "success": True,
        "message": f"Access granted: {request.username} → {request.service_name}",
        "permission": response.data[0]
    }


@app.delete("/permissions")
def remove_permission(request: PermissionRequest):
    # Find user
    user_response = (
        supabase
        .table("users")
        .select("id")
        .eq("username", request.username)
        .execute()
    )

    if not user_response.data:
        return {
            "success": False,
            "message": f"User '{request.username}' not found"
        }

    # Find service
    service_response = (
        supabase
        .table("services")
        .select("id")
        .eq("service_name", request.service_name)
        .execute()
    )

    if not service_response.data:
        return {
            "success": False,
            "message": f"Service '{request.service_name}' not found"
        }

    user_id = user_response.data[0]["id"]
    service_id = service_response.data[0]["id"]

    # Check permission
    existing = (
        supabase
        .table("permissions")
        .select("id")
        .eq("user_id", user_id)
        .eq("service_id", service_id)
        .execute()
    )

    if not existing.data:
        return {
            "success": False,
            "message": "Permission does not exist"
        }

    (
        supabase
        .table("permissions")
        .delete()
        .eq("user_id", user_id)
        .eq("service_id", service_id)
        .execute()
    )

    return {
        "success": True,
        "message": f"Access removed: {request.username} ✕ {request.service_name}"
    }