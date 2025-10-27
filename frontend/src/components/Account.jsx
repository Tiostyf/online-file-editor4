// src/components/Account.jsx
import React, { useState, useRef, useEffect } from 'react';
import './Account.css';
import api from '../api';
import confetti from 'canvas-confetti';

const Account = ({ user, onLogout, onLogin, isLoggedIn }) => {
  const [activeSection, setActiveSection] = useState('profile');
  const [isEditing, setIsEditing] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const fileInputRef = useRef(null);

  const [formData, setFormData] = useState({
    username: user?.username || '',
    email: user?.email || '',
    fullName: user?.profile?.fullName || '',
    company: user?.profile?.company || '',
    phone: user?.profile?.phone || '',
    location: user?.profile?.location || '',
    avatar: user?.profile?.avatar || null
  });

  const [authState, setAuthState] = useState({ email: '', password: '', username: '' });
  const [avatarPreview, setAvatarPreview] = useState(user?.profile?.avatar || null);

  // === DARK MODE ===
  useEffect(() => {
    document.body.classList.toggle('dark-mode', darkMode);
  }, [darkMode]);

  // === PREMIUM FEATURES ===
  const accountFeatures = [
    { icon: 'fas fa-user-shield', title: 'Advanced Security', desc: '2FA, login alerts, session control' },
    { icon: 'fas fa-palette', title: 'Custom Themes', desc: 'Dark mode, color schemes, layout presets' },
    { icon: 'fas fa-bell', title: 'Smart Notifications', desc: 'Priority alerts, quiet hours, custom triggers' },
    { icon: 'fas fa-cloud', title: 'Cloud Sync', desc: 'Google Drive, Dropbox, OneDrive integration' },
    { icon: 'fas fa-users-cog', title: 'Team Management', desc: 'Roles, permissions, activity logs' },
    { icon: 'fas fa-chart-pie', title: 'Analytics', desc: 'Compression & trends, savings, predictions' },
    { icon: 'fas fa-share-alt', title: 'Smart Sharing', desc: 'Links with expiry, passwords, limits' },
    { icon: 'fas fa-history', title: 'Audit Logs', desc: 'Full activity trail with timestamps' },
    { icon: 'fas fa-cog', title: 'Advanced Settings', desc: 'Export/import config, API access' },
    { icon: 'fas fa-heart', title: 'Premium Support', desc: '24/7 priority, dedicated manager' }
  ];

  // === INPUT HANDLERS ===
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    setErrors(prev => ({ ...prev, [name]: '' }));
  };

  const handleAuthChange = (e) => {
    const { name, value } = e.target;
    setAuthState(prev => ({ ...prev, [name]: value }));
    setErrors(prev => ({ ...prev, [name]: '' }));
  };

  // === VALIDATION ===
  const validateForm = () => {
    const newErrors = {};
    if (!formData.email.includes('@')) newErrors.email = 'Invalid email';
    if (formData.phone && !/^\+?[\d\s-]{10,}$/.test(formData.phone)) newErrors.phone = 'Invalid phone';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validateAuth = () => {
    const newErrors = {};
    if (authMode === 'register') {
      if (!authState.username) newErrors.username = 'Username required';
      if (authState.username.length < 3) newErrors.username = 'Username too short';
    }
    if (!authState.email.includes('@')) newErrors.email = 'Invalid email';
    if (authState.password.length < 6) newErrors.password = 'Password too short';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // === SAVE PROFILE ===
  const handleSave = async () => {
    if (!validateForm()) return;
    setLoading(true);
    try {
      const updateData = {
        fullName: formData.fullName,
        company: formData.company,
        phone: formData.phone,
        location: formData.location,
      };
      const updatedUser = await api.updateProfile(updateData);
      onLogin(updatedUser, localStorage.getItem('token'));
      confetti({ particleCount: 80, spread: 70, origin: { y: 0.6 } });
      setIsEditing(false);
    } catch (err) {
      alert(err.message || 'Save failed');
    } finally {
      setLoading(false);
    }
  };

  // === AVATAR ===
  const handleAvatarChange = (e) => {
    const file = e.target.files[0];
    if (file && file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setAvatarPreview(reader.result);
        setFormData(prev => ({ ...prev, avatar: reader.result }));
      };
      reader.readAsDataURL(file);
    }
  };

  // === LOGIN ===
  const submitLogin = async (e) => {
    e.preventDefault();
    if (!validateAuth()) return;
    setLoading(true);
    try {
      const res = await api.login(authState.email, authState.password);
      onLogin(res.user, res.token);
    } catch (err) {
      alert(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  // === REGISTER — FIXED 400 ===
  const submitRegister = async (e) => {
    e.preventDefault();
    if (!validateAuth()) return;
    setLoading(true);
    try {
      const res = await api.register(
        authState.username.trim(),
        authState.email.toLowerCase().trim(),
        authState.password
      );
      onLogin(res.user, res.token);
    } catch (err) {
      alert(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  // === NOT LOGGED IN ===
  if (!isLoggedIn) {
    return (
      <div className="account-login">
        <div className="login-glass">
          <div className="login-header">
            <i className="fas fa-shield-alt"></i>
            <h1>File Studio <span className="pro">Pro</span></h1>
            <p>Secure access to your file workspace</p>
          </div>

          <div className="auth-tabs">
            <button className={authMode === 'login' ? 'active' : ''} onClick={() => setAuthMode('login')}>
              <i className="fas fa-sign-in-alt"></i> Login
            </button>
            <button className={authMode === 'register' ? 'active' : ''} onClick={() => setAuthMode('register')}>
              <i className="fas fa-user-plus"></i> Register
            </button>
          </div>

          <form className="auth-form" onSubmit={authMode === 'login' ? submitLogin : submitRegister}>
            {authMode === 'register' && (
              <div className="input-group">
                <i className="fas fa-user"></i>
                <input
                  name="username"
                  placeholder="Username"
                  value={authState.username}
                  onChange={handleAuthChange}
                  required
                  minLength="3"
                />
                {errors.username && <span className="error-text">{errors.username}</span>}
              </div>
            )}
            <div className="input-group">
              <i className="fas fa-envelope"></i>
              <input
                name="email"
                type="email"
                placeholder="Email"
                value={authState.email}
                onChange={handleAuthChange}
                required
              />
              {errors.email && <span className="error-text">{errors.email}</span>}
            </div>
            <div className="input-group">
              <i className="fas fa-lock"></i>
              <input
                name="password"
                type="password"
                placeholder="Password"
                value={authState.password}
                onChange={handleAuthChange}
                required
                minLength="6"
              />
              {errors.password && <span className="error-text">{errors.password}</span>}
            </div>
            <button className="auth-btn" type="submit" disabled={loading}>
              {loading ? 'Processing...' : authMode === 'login' ? 'Login Securely' : 'Create Account'}
            </button>
          </form>

          <div className="login-features">
            <h3>Premium Features Included</h3>
            <div className="feature-chips">
              {['AES-256 Encryption', '2FA', 'Cloud Sync', 'Unlimited Files'].map(f => (
                <span key={f} className="chip"><i className="fas fa-check"></i> {f}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // === LOGGED IN ===
  return (
    <div className={`account-studio ${darkMode ? 'dark' : ''}`}>
      <button className="theme-toggle" onClick={() => setDarkMode(!darkMode)}>
        <i className={`fas ${darkMode ? 'fa-sun' : 'fa-moon'}`}></i>
      </button>

      <div className="account-container">
        {/* Sidebar */}
        <aside className="account-sidebar">
          <div className="profile-card">
            <div className="avatar-wrapper" onClick={() => isEditing && fileInputRef.current?.click()}>
              {avatarPreview ? (
                <img src={avatarPreview} alt="Avatar" className="avatar-img" />
              ) : (
                <div className="avatar-placeholder">
                  <i className="fas fa-user"></i>
                </div>
              )}
              {isEditing && <div className="avatar-overlay"><i className="fas fa-camera"></i></div>}
            </div>
            <input ref={fileInputRef} type="file" accept="image/*" onChange={handleAvatarChange} className="hidden-input" />

            <h3>{formData.fullName || 'User'}</h3>
            <p className="email">{formData.email}</p>
            <div className="premium-badge">
              <i className="fas fa-crown"></i> Premium
            </div>

            <div className="stats-grid">
              <div className="stat-card">
                <i className="fas fa-file-alt"></i>
                <div>
                  <strong>{user?.stats?.totalFiles || 0}</strong>
                  <span>Files</span>
                </div>
              </div>
              <div className="stat-card">
                <i className="fas fa-save"></i>
                <div>
                  <strong>{((user?.stats?.spaceSaved || 0) / 1024 / 1024).toFixed(1)}MB</strong>
                  <span>Saved</span>
                </div>
              </div>
            </div>
          </div>

          <nav className="nav-menu">
            {[
              { id: 'profile', icon: 'fas fa-user', label: 'Profile' },
              { id: 'security', icon: 'fas fa-shield-alt', label: 'Security' },
              { id: 'storage', icon: 'fas fa-cloud', label: 'Storage' },
              { id: 'notifications', icon: 'fas fa-bell', label: 'Notifications' },
              { id: 'billing', icon: 'fas fa-credit-card', label: 'Billing' },
              { id: 'preferences', icon: 'fas fa-cog', label: 'Preferences' }
            ].map(item => (
              <button
                key={item.id}
                className={`nav-item ${activeSection === item.id ? 'active' : ''}`}
                onClick={() => setActiveSection(item.id)}
              >
                <i className={item.icon}></i>
                {item.label}
              </button>
            ))}
          </nav>

          <button className="logout-btn" onClick={onLogout}>
            <i className="fas fa-sign-out-alt"></i> Logout
          </button>
        </aside>

        {/* Main Content */}
        <main className="account-main">
          {activeSection === 'profile' && (
            <section className="profile-section">
              <div className="section-header">
                <h2>Profile Information</h2>
                <button className="edit-toggle" onClick={() => setIsEditing(!isEditing)}>
                  <i className={`fas fa-${isEditing ? 'save' : 'edit'}`}></i>
                  {isEditing ? 'Save' : 'Edit'}
                </button>
              </div>

              <div className="profile-grid">
                {[
                  { label: 'Username', name: 'username', icon: 'fas fa-user', disabled: true },
                  { label: 'Email', name: 'email', icon: 'fas fa-envelope', type: 'email', disabled: true },
                  { label: 'Full Name', name: 'fullName', icon: 'fas fa-id-card' },
                  { label: 'Company', name: 'company', icon: 'fas fa-building' },
                  { label: 'Phone', name: 'phone', icon: 'fas fa-phone', type: 'tel' },
                  { label: 'Location', name: 'location', icon: 'fas fa-map-marker-alt' }
                ].map(field => (
                  <div key={field.name} className="input-card">
                    <label><i className={field.icon}></i> {field.label}</label>
                    <input
                      type={field.type || 'text'}
                      name={field.name}
                      value={formData[field.name]}
                      onChange={handleInputChange}
                      disabled={!isEditing || field.disabled}
                      className={errors[field.name] ? 'error' : ''}
                    />
                    {errors[field.name] && <span className="error-text">{errors[field.name]}</span>}
                  </div>
                ))}
              </div>

              {isEditing && (
                <div className="action-buttons">
                  <button className="cancel-btn" onClick={() => setIsEditing(false)}>Cancel</button>
                  <button className="save-btn" onClick={handleSave} disabled={loading}>
                    {loading ? 'Saving...' : 'Save Changes'}
                  </button>
                </div>
              )}
            </section>
          )}

          {activeSection === 'security' && (
            <section className="security-section">
              <h2>Security Center</h2>
              <div className="security-grid">
                {[
                  { icon: 'fas fa-lock', title: 'Two-Factor Auth', desc: 'Add extra protection', action: 'Enable', color: '#4facfe' },
                  { icon: 'fas fa-history', title: 'Login History', desc: 'Last login: 2 hours ago', action: 'View', color: '#43e97f' },
                  { icon: 'fas fa-key', title: 'Change Password', desc: 'Strong password recommended', action: 'Change', color: '#fa709a' }
                ].map(item => (
                  <div key={item.title} className="security-card" style={{ '--card-color': item.color }}>
                    <i className={item.icon}></i>
                    <div>
                      <h4>{item.title}</h4>
                      <p>{item.desc}</p>
                    </div>
                    <button className="action-btn">{item.action}</button>
                  </div>
                ))}
              </div>
            </section>
          )}
        </main>
      </div>

      {/* Premium Features */}
      <section className="premium-features">
        <h2>Why Go Premium?</h2>
        <div className="features-grid">
          {accountFeatures.map((f, i) => (
            <div key={i} className="feature-card">
              <div className="feature-icon"><i className={f.icon}></i></div>
              <h3>{f.title}</h3>
              <p>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Upgrade CTA */}
      <div className="upgrade-cta">
        <div className="cta-content">
          <i className="fas fa-crown"></i>
          <h3>Upgrade to Premium</h3>
          <p>Unlock all features • No limits • Priority support</p>
          <button className="upgrade-btn">Go Premium Now</button>
        </div>
      </div>
    </div>
  );
};

export default Account;