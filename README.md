# Simplified Kerberos Authentication Protocol

A web-based virtual laboratory that demonstrates the working of a simplified Kerberos Authentication Protocol using FastAPI, React, Python Cryptography, and Supabase.

## 🌐 Live Demo

**Virtual Lab:**  
https://simplified-kerberos.vercel.app/

**Backend API:**  
https://backend-ten-olive-35.vercel.app/

**API Documentation:**  
https://backend-ten-olive-35.vercel.app/docs

---

## 📌 Project Overview

Kerberos is a network authentication protocol that uses tickets and symmetric-key cryptography to securely authenticate users and provide access to network services.

This project implements a **simplified educational version of Kerberos** and provides an interactive web-based virtual laboratory to visualize the authentication and authorization process.

The system demonstrates the communication between:

- Client
- Authentication Server (AS)
- Ticket Granting Server (TGS)
- Service Server

The project also includes user authentication, service management, and permission-based access control using Supabase.

---

## 🔐 Kerberos Authentication Flow

The simplified authentication process follows these stages:

```text
             Login
               │
               ▼
          ┌─────────┐
          │ Client  │
          └────┬────┘
               │
               ▼
     ┌────────────────────┐
     │ Authentication     │
     │ Server (AS)        │
     └─────────┬──────────┘
               │
               │ Ticket Granting Ticket (TGT)
               ▼
     ┌────────────────────┐
     │ Ticket Granting    │
     │ Server (TGS)       │
     └─────────┬──────────┘
               │
               │ Service Ticket
               ▼
     ┌────────────────────┐
     │ Service Server     │
     └─────────┬──────────┘
               │
               ▼
       Access Decision
       ┌────────┴────────┐
       │                 │
       ▼                 ▼
   Granted             Denied
