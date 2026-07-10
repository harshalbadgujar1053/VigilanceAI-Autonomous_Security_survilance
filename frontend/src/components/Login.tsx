import React, { useState } from 'react';
import { Eye, EyeOff, Shield, AlertTriangle, Lock } from 'lucide-react';
import { motion } from 'motion/react';
import CyberBackground from './CyberBackground';
import VigilanceLogo from './VigilanceLogo';

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!username.trim() || !password.trim()) {
      setError('Please fill in all credentials.');
      return;
    }

    setLoading(true);

    setTimeout(() => {
      if (username === 'Vigilance-AI' && password === 'VigilanceAI@123') {
        localStorage.setItem('vigilance_auth', 'true');
        onLogin();
      } else {
        setError('Invalid username or password. Please try again.');
        setLoading(false);
      }
    }, 800);
  };

  return (
    <div id="login-container" className="login-page">
      <CyberBackground mode="light" />
      
      {/* Glassmorphic Login Card */}
      <div id="login-card" className="login-card" style={{ position: 'relative', zIndex: 10 }}>
        {/* Sci-Fi HUD Bracket Overlays */}
        <div className="hud-brackets">
          <div className="hud-corner top-left"></div>
          <div className="hud-corner top-right"></div>
          <div className="hud-corner bottom-left"></div>
          <div className="hud-corner bottom-right"></div>
          <div className="hud-side-line left"></div>
          <div className="hud-side-line right"></div>
        </div>

        <div className="login-logo-row">
          <div className="logo-icon-container" style={{ background: 'transparent', boxShadow: 'none', width: 'auto', height: 'auto' }}>
            <VigilanceLogo size={52} />
          </div>
          <span className="brand-name">Vigilance AI</span>
        </div>

        <div className="login-header">
          <h2>Welcome back</h2>
          <p>Sign in to access dashboard</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              placeholder="Enter your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={loading}
              autoComplete="username"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <div className="password-input-wrapper">
              <input
                id="password"
                type={showPass ? 'text' : 'password'}
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                autoComplete="current-password"
                required
              />
              <button
                id="toggle-password"
                type="button"
                className="password-toggle-btn"
                onClick={() => setShowPass(!showPass)}
                disabled={loading}
                title={showPass ? 'Hide Password' : 'Show Password'}
              >
                {showPass ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          {error && (
            <div id="login-error-alert" className="error-alert-box">
              <AlertTriangle size={18} className="error-alert-icon" />
              <span>{error}</span>
            </div>
          )}

          <button
            id="login-submit-btn"
            type="submit"
            className="login-submit-btn"
            disabled={loading}
          >
            {loading ? (
              <span className="spinner-wrapper">
                <span className="spinner small" />
                Signing in...
              </span>
            ) : (
              <span className="button-inner-content">
                Sign in
              </span>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
