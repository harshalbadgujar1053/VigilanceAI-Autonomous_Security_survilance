import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import Login from './components/Login';

function Root() {
  const [loggedIn, setLoggedIn] = React.useState(
    localStorage.getItem('vigilance_auth') === 'true'
  );

  if (!loggedIn) {
    return <Login onLogin={() => setLoggedIn(true)} />;
  }
  return <App onLogout={() => {
    localStorage.removeItem('vigilance_auth');
    setLoggedIn(false);
  }} />;
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<React.StrictMode><Root /></React.StrictMode>);
