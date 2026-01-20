import { useNavigate } from 'react-router-dom';

export function Login() {
  const navigate = useNavigate();

  const handleLogin = () => {
    // Web3Auth integration in Phase 2
    navigate('/dashboard');
  };

  return (
    <div className="login-container">
      <h1>CipherBox</h1>
      <p>Zero-knowledge encrypted cloud storage</p>
      <button onClick={handleLogin} className="login-button">
        Connect Wallet
      </button>
      <p className="login-note">
        Web3Auth integration coming in Phase 2
      </p>
    </div>
  );
}
