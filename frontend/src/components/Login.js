import { useState } from 'react';

const CREDENTIALS = {
  username: 'Vigilance-AI',
  password: 'VigilanceAI@123',
};

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setTimeout(() => {
      if (username === CREDENTIALS.username && password === CREDENTIALS.password) {
        localStorage.setItem('vigilance_auth', 'true');
        onLogin();
      } else {
        setError('Invalid username or password. Please try again.');
        setLoading(false);
      }
    }, 800);
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0a1628 0%, #0f2044 50%, #1a365d 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif',
      position: 'relative',
      overflow: 'hidden',
    }}>

      {/* Background grid pattern */}
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: 'linear-gradient(rgba(99,179,237,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(99,179,237,0.03) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
      }}/>

      {/* Glow effects */}
      <div style={{ position:'absolute', top:'20%', left:'15%', width:'300px', height:'300px', background:'rgba(49,130,206,0.08)', borderRadius:'50%', filter:'blur(80px)' }}/>
      <div style={{ position:'absolute', bottom:'20%', right:'15%', width:'250px', height:'250px', background:'rgba(56,161,105,0.06)', borderRadius:'50%', filter:'blur(80px)' }}/>

      {/* Login Card */}
      <div style={{
        background: 'rgba(255,255,255,0.04)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '16px',
        padding: '48px 44px',
        width: '100%',
        maxWidth: '420px',
        boxShadow: '0 24px 64px rgba(0,0,0,0.4)',
        position: 'relative',
        zIndex: 1,
      }}>

        {/* Logo + Brand */}
        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <img
            src="/logo.png"
            alt="Vigilance AI"
            style={{
              width: '80px', height: '80px', objectFit: 'contain',
              filter: 'drop-shadow(0 0 20px rgba(99,179,237,0.8))',
              marginBottom: '16px',
            }}
          />
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#fff', letterSpacing: '0.02em', marginBottom: '4px' }}>
            Vigilance AI
          </div>
          <div style={{ fontSize: '11px', color: '#90cdf4', letterSpacing: '0.16em', textTransform: 'uppercase' }}>
            Autonomous Security Surveillance
          </div>
          <div style={{ marginTop: '12px', fontSize: '12px', color: 'rgba(255,255,255,0.35)', letterSpacing: '0.04em' }}>
            SOC Analyst Portal — Restricted Access
          </div>
        </div>

        {/* Divider */}
        <div style={{ height: '1px', background: 'linear-gradient(90deg, transparent, rgba(99,179,237,0.3), transparent)', marginBottom: '28px' }}/>

        {/* Form */}
        <form onSubmit={handleSubmit}>

          {/* Username */}
          <div style={{ marginBottom: '18px' }}>
            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: '#90cdf4', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '8px' }}>
              Username
            </label>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', fontSize: '15px', opacity: 0.5 }}>👤</span>
              <input
                type="text"
                value={username}
                onChange={e => { setUsername(e.target.value); setError(''); }}
                placeholder="Enter username"
                autoComplete="username"
                style={{
                  width: '100%', padding: '12px 14px 12px 40px',
                  background: 'rgba(255,255,255,0.06)',
                  border: `1px solid ${error ? 'rgba(252,129,129,0.5)' : 'rgba(255,255,255,0.12)'}`,
                  borderRadius: '8px', color: '#fff', fontSize: '14px',
                  outline: 'none', transition: 'border-color 0.2s',
                  boxSizing: 'border-box',
                }}
                onFocus={e => e.target.style.borderColor = 'rgba(99,179,237,0.6)'}
                onBlur={e => e.target.style.borderColor = error ? 'rgba(252,129,129,0.5)' : 'rgba(255,255,255,0.12)'}
              />
            </div>
          </div>

          {/* Password */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: '#90cdf4', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '8px' }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', fontSize: '15px', opacity: 0.5 }}>🔒</span>
              <input
                type={showPass ? 'text' : 'password'}
                value={password}
                onChange={e => { setPassword(e.target.value); setError(''); }}
                placeholder="Enter password"
                autoComplete="current-password"
                style={{
                  width: '100%', padding: '12px 44px 12px 40px',
                  background: 'rgba(255,255,255,0.06)',
                  border: `1px solid ${error ? 'rgba(252,129,129,0.5)' : 'rgba(255,255,255,0.12)'}`,
                  borderRadius: '8px', color: '#fff', fontSize: '14px',
                  outline: 'none', transition: 'border-color 0.2s',
                  boxSizing: 'border-box',
                }}
                onFocus={e => e.target.style.borderColor = 'rgba(99,179,237,0.6)'}
                onBlur={e => e.target.style.borderColor = error ? 'rgba(252,129,129,0.5)' : 'rgba(255,255,255,0.12)'}
              />
              <button
                type="button"
                onClick={() => setShowPass(v => !v)}
                style={{
                  position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'rgba(255,255,255,0.4)', fontSize: '14px', padding: '2px',
                }}
              >
                {showPass ? '🙈' : '👁'}
              </button>
            </div>
          </div>

          {/* Error message */}
          {error && (
            <div style={{
              marginBottom: '18px', padding: '10px 14px',
              background: 'rgba(229,62,62,0.12)', border: '1px solid rgba(252,129,129,0.3)',
              borderRadius: '7px', fontSize: '12px', color: '#fc8181',
              display: 'flex', alignItems: 'center', gap: '8px',
            }}>
              <span>✕</span> {error}
            </div>
          )}

          {/* Login button */}
          <button
            type="submit"
            disabled={loading || !username || !password}
            style={{
              width: '100%', padding: '13px',
              background: loading || !username || !password
                ? 'rgba(255,255,255,0.08)'
                : 'linear-gradient(135deg, #1a56a0, #2b6cb0)',
              border: 'none', borderRadius: '8px',
              color: loading || !username || !password ? 'rgba(255,255,255,0.3)' : '#fff',
              fontSize: '14px', fontWeight: 700, letterSpacing: '0.04em',
              cursor: loading || !username || !password ? 'default' : 'pointer',
              boxShadow: loading || !username || !password ? 'none' : '0 4px 16px rgba(26,86,160,0.4)',
              transition: 'all 0.2s',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
            }}
          >
            {loading ? (
              <>
                <span style={{ width:'14px', height:'14px', border:'2px solid rgba(255,255,255,0.3)', borderTopColor:'#fff', borderRadius:'50%', animation:'spin 0.7s linear infinite', display:'inline-block' }}/>
                Authenticating…
              </>
            ) : '🔐 Sign In to Dashboard'}
          </button>
        </form>

        {/* Footer */}
        <div style={{ marginTop: '28px', textAlign: 'center', fontSize: '10px', color: 'rgba(255,255,255,0.2)', lineHeight: 1.8 }}>
          B.Tech Major Project · Vigilance AI<br/>
          Unauthorized access is strictly prohibited
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        input::placeholder { color: rgba(255,255,255,0.25); }
        input:-webkit-autofill {
          -webkit-box-shadow: 0 0 0 30px #0f2044 inset !important;
          -webkit-text-fill-color: #fff !important;
        }
      `}</style>
    </div>
  );
}
