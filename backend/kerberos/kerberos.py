from dataclasses import dataclass
from datetime import datetime, timedelta

from .crypto_utils import (
    generate_key,
    encrypt,
    decrypt,
    derive_key_from_password
)


@dataclass
class TGT:
    username: str
    client_tgs_key: bytes
    issue_time: datetime
    expiry_time: datetime


@dataclass
class ServiceTicket:
    username: str
    service_name: str
    client_service_key: bytes
    issue_time: datetime
    expiry_time: datetime


@dataclass
class Authenticator:
    username: str
    timestamp: datetime


class AuthenticationServer:

    def __init__(self, tgs_key: bytes):
        # Secret key shared between AS and TGS
        self.tgs_key = tgs_key

    def authenticate_client(self, username: str, password: str):

        # The username and password are already verified
        # against the Supabase users table in main.py.

        print(f"[AS] User '{username}' authenticated successfully.")

        # Step 1: Generate Client-TGS session key
        client_tgs_key = generate_key()

        # Step 2: Create TGT data
        issue_time = datetime.now()
        expiry_time = issue_time + timedelta(minutes=10)

        tgt_data = (
            f"{username}|"
            f"{client_tgs_key.hex()}|"
            f"{issue_time.isoformat()}|"
            f"{expiry_time.isoformat()}"
        )

        # Step 3: Encrypt TGT using TGS secret key
        encrypted_tgt = encrypt(
            tgt_data,
            self.tgs_key
        )

        print("[AS] TGT generated successfully.")

        # Step 4: Derive the client's long-term key
        client_key = derive_key_from_password(
            password,
            username.encode("utf-8")
        )

        # Step 5: Protect Client-TGS session key and TGT
        client_data = (
            f"{client_tgs_key.hex()}|"
            f"{encrypted_tgt}"
        )

        encrypted_client_data = encrypt(
            client_data,
            client_key
        )

        # Step 6: Return protected response
        return encrypted_client_data


class TicketGrantingServer:

    def __init__(self, tgs_key: bytes, service_key: bytes):

        # Secret key shared with the Authentication Server
        self.tgs_key = tgs_key

        # Secret key shared with the Service Server
        self.service_key = service_key

    def issue_service_ticket(
        self,
        encrypted_tgt: str,
        service_name: str,
        encrypted_authenticator: str
    ):

        # Step 1: Decrypt the TGT using Ktgs
        tgt_data = decrypt(
            encrypted_tgt,
            self.tgs_key
        )

        # Step 2: Extract TGT information
        (
            username,
            client_tgs_key_hex,
            issue_time,
            expiry_time
        ) = tgt_data.split("|")

        client_tgs_key = bytes.fromhex(
            client_tgs_key_hex
        )

        print(
            f"[TGS] TGT received for user '{username}'."
        )

        # Step 3: Check TGT expiry
        current_time = datetime.now()
        expiry = datetime.fromisoformat(
            expiry_time
        )

        if current_time > expiry:
            raise ValueError("TGT has expired")

        # Step 4: Decrypt Authenticator using Kc_tgs
        authenticator_data = decrypt(
            encrypted_authenticator,
            client_tgs_key
        )

        auth_username, auth_timestamp = (
            authenticator_data.split("|")
        )

        auth_time = datetime.fromisoformat(
            auth_timestamp
        )

        print(
            f"[TGS] Authenticator received "
            f"for user '{auth_username}'."
        )

        # Step 5: Verify username
        if auth_username != username:
            raise ValueError(
                "Authenticator username mismatch"
            )

        # Step 6: Check timestamp freshness
        time_difference = abs(
            (current_time - auth_time).total_seconds()
        )

        if time_difference > 300:
            raise ValueError(
                "Authenticator timestamp is too old"
            )

        print(
            "[TGS] Authenticator verified successfully."
        )

        # Step 7: Generate Client-Service session key
        client_service_key = generate_key()

        # Step 8: Create Service Ticket
        ticket_issue_time = current_time
        ticket_expiry_time = (
            current_time + timedelta(minutes=10)
        )

        service_ticket_data = (
            f"{username}|"
            f"{service_name}|"
            f"{client_service_key.hex()}|"
            f"{ticket_issue_time.isoformat()}|"
            f"{ticket_expiry_time.isoformat()}"
        )

        # Step 9: Encrypt Service Ticket using Ks
        encrypted_service_ticket = encrypt(
            service_ticket_data,
            self.service_key
        )

        print(
            "[TGS] Service Ticket generated successfully."
        )

        # Step 10: Return Client-Service session key + ticket
        return (
            f"{client_service_key.hex()}|"
            f"{encrypted_service_ticket}"
        )


class ServiceServer:

    def __init__(self, service_key: bytes):

        # Secret key shared with the TGS
        self.service_key = service_key

    def authenticate_client(
        self,
        encrypted_service_ticket: str,
        encrypted_authenticator: str
    ):

        # Step 1: Decrypt Service Ticket using Ks
        ticket_data = decrypt(
            encrypted_service_ticket,
            self.service_key
        )

        # Step 2: Extract ticket information
        (
            username,
            service_name,
            client_service_key_hex,
            issue_time,
            expiry_time
        ) = ticket_data.split("|")

        client_service_key = bytes.fromhex(
            client_service_key_hex
        )

        print(
            f"[Service] Service Ticket received "
            f"for user '{username}'."
        )

        print(
            f"[Service] Requested service: "
            f"{service_name}"
        )

        # Step 3: Check ticket expiry
        current_time = datetime.now()
        expiry = datetime.fromisoformat(
            expiry_time
        )

        if current_time > expiry:
            raise ValueError(
                "Service Ticket has expired"
            )

        # Step 4: Decrypt Authenticator using Kc_s
        authenticator_data = decrypt(
            encrypted_authenticator,
            client_service_key
        )

        auth_username, auth_timestamp = (
            authenticator_data.split("|")
        )

        auth_time = datetime.fromisoformat(
            auth_timestamp
        )

        print(
            f"[Service] Authenticator received "
            f"for user '{auth_username}'."
        )

        # Step 5: Verify username
        if auth_username != username:
            raise ValueError(
                "Authenticator username mismatch"
            )

        # Step 6: Check timestamp freshness
        time_difference = abs(
            (current_time - auth_time).total_seconds()
        )

        if time_difference > 300:
            raise ValueError(
                "Authenticator timestamp is too old"
            )

        print(
            "[Service] Authenticator verified successfully."
        )

        # Authentication successful
        print(
            f"[Service] User '{username}' "
            f"authenticated successfully."
        )

        return True