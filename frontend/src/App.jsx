import { useState, useEffect } from "react"
import "./App.css"

const API_BASE_URL = "https://backend-ten-olive-35.vercel.app"

function App() {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")

  const [message, setMessage] = useState("")
  const [loggedIn, setLoggedIn] = useState(false)

  // Dynamic services from FastAPI / Supabase
  const [services, setServices] = useState([])
  const [serviceName, setServiceName] = useState("")

  const [serviceTicket, setServiceTicket] = useState("")
  const [ticketMessage, setTicketMessage] = useState("")

  const [accessMessage, setAccessMessage] = useState("")
  const [accessGranted, setAccessGranted] = useState(null)

  // Dynamic stage of the Kerberos process
  const [stage, setStage] = useState("login")

  // Load services from FastAPI
  useEffect(() => {
    const loadServices = async () => {
      try {
        const response = await fetch(
          `${API_BASE_URL}/services`
        )

        const data = await response.json()

        if (data.success) {
          setServices(data.services)

          // Select first service automatically
          if (data.services.length > 0) {
            setServiceName(data.services[0].service_name)
          }
        }
      } catch (error) {
        console.error("Could not load services:", error)
      }
    }

    loadServices()
  }, [])

  const handleLogin = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/login`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            password,
          }),
        }
      )

      const data = await response.json()

      setMessage(data.message)

      if (data.success) {
        setLoggedIn(true)
        setStage("as")
      } else {
        setLoggedIn(false)
        setStage("login")
      }
    } catch (error) {
      setMessage("Could not connect to FastAPI backend.")
      setLoggedIn(false)
      setStage("login")
    }
  }

  const handleRequestService = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/request-service-ticket`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            service_name: serviceName,
          }),
        }
      )

      const data = await response.json()

      if (data.success) {
        setServiceTicket(data.service_ticket)
        setTicketMessage("Service ticket generated successfully.")
        setStage("tgs")
      } else {
        setServiceTicket("")
        setTicketMessage(data.message)
        setStage("as")
      }

      setAccessMessage("")
      setAccessGranted(null)
    } catch (error) {
      setTicketMessage("Could not connect to FastAPI backend.")
    }
  }

  const handleAccessService = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/access-service`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            service_name: serviceName,
            service_ticket: serviceTicket,
          }),
        }
      )

      const data = await response.json()

      setAccessMessage(data.message)
      setAccessGranted(data.success)
      setStage(data.success ? "granted" : "denied")
    } catch (error) {
      setAccessMessage("Could not connect to FastAPI backend.")
      setAccessGranted(false)
      setStage("denied")
    }
  }

  const handleLogout = () => {
    setLoggedIn(false)
    setUsername("")
    setPassword("")
    setMessage("")
    setServiceName(
      services.length > 0 ? services[0].service_name : ""
    )
    setServiceTicket("")
    setTicketMessage("")
    setAccessMessage("")
    setAccessGranted(null)
    setStage("login")
  }

  return (
    <div className="app">
      <header className="header">
        <div className="header-content">
          <div>
            <p className="eyebrow">CRYPTOGRAPHY • VIRTUAL LAB</p>
            <h1>Kerberos Authentication</h1>
            <p className="subtitle">Web-Based Virtual Laboratory</p>
          </div>
        </div>
      </header>

      <main className="container">

        {/* INTRO */}
        <section className="intro">
          <h2>Kerberos Authentication Lab</h2>
          <p>
            Explore authentication, ticket generation and
            service authorization using a simplified Kerberos
            protocol.
          </p>
        </section>


        {/* KERBEROS FLOW */}
        <section className="card">
          <div className="section-title">
            <span>01</span>

            <div>
              <h2>Kerberos Authentication Flow</h2>
              <p>Authentication and authorization process</p>
            </div>
          </div>


          <div className="flow">

            {/* CLIENT */}
            <div
              className={`flow-box ${
                stage !== "login" ? "active" : ""
              }`}
            >
              <div className="flow-number">
                {stage !== "login" ? "✓" : "1"}
              </div>

              <h3>Client</h3>

              <p>
                {stage !== "login"
                  ? "Authenticated"
                  : "User Login"}
              </p>
            </div>


            <div className="arrow">→</div>


            {/* AS */}
            <div
              className={`flow-box ${
                stage === "as" ||
                stage === "tgs" ||
                stage === "granted" ||
                stage === "denied"
                  ? "active"
                  : ""
              }`}
            >
              <div className="flow-number">
                {stage === "as" ||
                stage === "tgs" ||
                stage === "granted" ||
                stage === "denied"
                  ? "✓"
                  : "2"}
              </div>

              <h3>AS</h3>

              <p>
                {stage === "as" ||
                stage === "tgs" ||
                stage === "granted" ||
                stage === "denied"
                  ? "TGT Issued"
                  : "Authentication Server"}
              </p>
            </div>


            <div className="arrow">→</div>


            {/* TGS */}
            <div
              className={`flow-box ${
                stage === "tgs" ||
                stage === "granted" ||
                stage === "denied"
                  ? "active"
                  : ""
              }`}
            >
              <div className="flow-number">
                {stage === "tgs" ||
                stage === "granted" ||
                stage === "denied"
                  ? "✓"
                  : "3"}
              </div>

              <h3>TGS</h3>

              <p>
                {stage === "tgs" ||
                stage === "granted" ||
                stage === "denied"
                  ? "Service Ticket Issued"
                  : "Ticket Granting Server"}
              </p>
            </div>


            <div className="arrow">→</div>


            {/* SERVICE */}
            <div
              className={`flow-box ${
                stage === "granted"
                  ? "active granted-stage"
                  : stage === "denied"
                  ? "active denied-stage"
                  : ""
              }`}
            >
              <div className="flow-number">
                {stage === "granted"
                  ? "✓"
                  : stage === "denied"
                  ? "✕"
                  : "4"}
              </div>

              <h3>Service</h3>

              <p>
                {stage === "granted"
                  ? "Access Granted"
                  : stage === "denied"
                  ? "Access Denied"
                  : "Access Decision"}
              </p>
            </div>

          </div>


          {/* DYNAMIC STAGE MESSAGE */}
          <div className={`stage-status ${stage}`}>

            <div className="stage-status-icon">
              {stage === "login" && "1"}
              {stage === "as" && "2"}
              {stage === "tgs" && "3"}
              {stage === "granted" && "✓"}
              {stage === "denied" && "✕"}
            </div>

            <div>
              <strong>
                {stage === "login" &&
                  "Waiting for client authentication"}

                {stage === "as" &&
                  "Authentication Server completed"}

                {stage === "tgs" &&
                  "Ticket Granting Server completed"}

                {stage === "granted" &&
                  "Kerberos authentication and authorization completed"}

                {stage === "denied" &&
                  "Authentication completed, but authorization failed"}
              </strong>

              <p>
                {stage === "login" &&
                  "Enter your credentials to begin the Kerberos authentication process."}

                {stage === "as" &&
                  "Client authenticated successfully and received a Ticket Granting Ticket (TGT)."}

                {stage === "tgs" &&
                  "TGS verified the request and generated a service ticket for the selected service."}

                {stage === "granted" &&
                  `User ${username} is authorized to access ${serviceName}.`}

                {stage === "denied" &&
                  `User ${username} does not have permission to access ${serviceName}.`}
              </p>
            </div>

          </div>
        </section>


        {/* LOGIN */}
        <section className="card">

          <div className="section-title">
            <span>02</span>

            <div>
              <h2>User Authentication</h2>

              <p>
                Authenticate the client with the
                Authentication Server
              </p>
            </div>
          </div>


          <div className="form">

            <label>Username</label>

            <input
              type="text"
              placeholder="Enter username"
              value={username}
              onChange={(e) =>
                setUsername(e.target.value)
              }
            />


            <label>Password</label>

            <input
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) =>
                setPassword(e.target.value)
              }
            />


            <button
              className="primary-button"
              onClick={handleLogin}
            >
              Authenticate
            </button>

          </div>


          {message && (
            <div
              className={
                loggedIn
                  ? "status success"
                  : "status error"
              }
            >
              {loggedIn ? "✓ " : "✕ "}
              {message}
            </div>
          )}

        </section>


        {/* AUTHENTICATED USER */}
        {loggedIn && (
          <>

            <div className="session-bar">

              <div>
                <span className="session-label">
                  AUTHENTICATED USER
                </span>

                <strong>{username}</strong>
              </div>


              <button
                className="logout-button"
                onClick={handleLogout}
              >
                Logout / New Login
              </button>

            </div>


            {/* SERVICE TICKET */}
            <section className="card">

              <div className="section-title">
                <span>03</span>

                <div>
                  <h2>Request Service Ticket</h2>

                  <p>
                    Request access to a protected service
                    through the Ticket Granting Server
                  </p>
                </div>
              </div>


              <div className="service-form">

                <div>

                  <label>Service</label>

                  <select
                    value={serviceName}
                    onChange={(e) => {

                      setServiceName(e.target.value)

                      setServiceTicket("")
                      setTicketMessage("")
                      setAccessMessage("")
                      setAccessGranted(null)

                      // Return to AS stage
                      setStage("as")
                    }}
                    disabled={services.length === 0}
                  >
                    {services.length === 0 ? (
                      <option value="">
                        No services available
                      </option>
                    ) : (
                      services.map((service) => (
                        <option
                          key={service.id}
                          value={service.service_name}
                        >
                          {service.service_name}
                        </option>
                      ))
                    )}
                  </select>

                </div>


                <button
                  className="primary-button"
                  onClick={handleRequestService}
                  disabled={!serviceName}
                >
                  Request Service Ticket
                </button>

              </div>


              {ticketMessage && (
                <div className="ticket-status">

                  <div className="ticket-icon">
                    ✓
                  </div>

                  <div>

                    <strong>
                      Service Ticket
                    </strong>

                    <p>
                      {ticketMessage}
                    </p>

                  </div>

                </div>
              )}

            </section>


            {/* SERVICE ACCESS */}
            {serviceTicket && (
              <section className="card">

                <div className="section-title">
                  <span>04</span>

                  <div>
                    <h2>Service Access</h2>

                    <p>
                      Verify the service ticket and check
                      user authorization
                    </p>
                  </div>
                </div>


                <div className="access-box">

                  <div className="access-info">

                    <div>
                      <span>User</span>
                      <strong>{username}</strong>
                    </div>

                    <div>
                      <span>Requested Service</span>
                      <strong>{serviceName}</strong>
                    </div>

                  </div>


                  <button
                    className="primary-button"
                    onClick={handleAccessService}
                  >
                    Access Service
                  </button>

                </div>


                {accessMessage && (
                  <div
                    className={
                      accessGranted
                        ? "access-result granted"
                        : "access-result denied"
                    }
                  >

                    <div className="result-icon">
                      {accessGranted ? "✓" : "✕"}
                    </div>

                    <div>

                      <h3>
                        {accessGranted
                          ? "Access Granted"
                          : "Access Denied"}
                      </h3>

                      <p>
                        {accessGranted
                          ? `User ${username} is authorized to access ${serviceName}.`
                          : `User ${username} is not authorized to access ${serviceName}.`}
                      </p>

                    </div>

                  </div>
                )}

              </section>
            )}

          </>
        )}


        <footer>
          <p>
            Kerberos Authentication Protocol • Simplified
            Educational Implementation
          </p>
        </footer>

      </main>
    </div>
  )
}

export default App