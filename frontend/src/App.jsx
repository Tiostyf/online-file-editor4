import React, { useState, useEffect } from 'react'
import Home from './components/Home.jsx'
import Edit from './components/Edit.jsx'
import History from './components/History.jsx'
import Account from './components/Account.jsx'
import Blog from './components/Blog.jsx'
import './App.css'

function App() {
  const [currentTab, setCurrentTab] = useState('home')
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [user, setUser] = useState(null)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) {
      verifyToken(token)
    }
  }, [])

  const verifyToken = async (token) => {
    try {
      const response = await fetch('/api/profile', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      if (response.ok) {
        const data = await response.json()
        setIsLoggedIn(true)
        setUser(data.data.user)
      } else {
        localStorage.removeItem('token')
      }
    } catch (error) {
      console.error('Token verification failed:', error)
      localStorage.removeItem('token')
    }
  }

  const handleLogin = (userData, token) => {
    setIsLoggedIn(true)
    setUser(userData)
    localStorage.setItem('token', token)
  }

  const handleLogout = () => {
    localStorage.removeItem('token')
    setIsLoggedIn(false)
    setUser(null)
    setCurrentTab('home')
  }

  const renderTab = () => {
    switch (currentTab) {
      case 'home':
        return <Home isLoggedIn={isLoggedIn} />
      case 'edit':
        return <Edit isLoggedIn={isLoggedIn} user={user} />
      case 'history':
        return <History isLoggedIn={isLoggedIn} user={user} />
      case 'account':
        return <Account user={user} onLogout={handleLogout} onLogin={handleLogin} isLoggedIn={isLoggedIn} />
      case 'blog':
        return <Blog />
      default:
        return <Home isLoggedIn={isLoggedIn} />
    }
  }

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-brand">
          <i className="fas fa-file-alt"></i>
          <span>Rio-Indus</span>
        </div>
        <div className="nav-tabs">
          <button 
            className={`tab-btn ${currentTab === 'home' ? 'active' : ''}`}
            onClick={() => setCurrentTab('home')}
          >
            <i className="fas fa-home"></i>
            Home
          </button>
          <button 
            className={`tab-btn ${currentTab === 'edit' ? 'active' : ''}`}
            onClick={() => setCurrentTab('edit')}
          >
            <i className="fas fa-edit"></i>
            Edit
          </button>
          <button 
            className={`tab-btn ${currentTab === 'history' ? 'active' : ''}`}
            onClick={() => setCurrentTab('history')}
          >
            <i className="fas fa-history"></i>
            History
          </button>
          <button 
            className={`tab-btn ${currentTab === 'account' ? 'active' : ''}`}
            onClick={() => setCurrentTab('account')}
          >
            <i className="fas fa-user"></i>
            Account
          </button>
          <button 
            className={`tab-btn ${currentTab === 'blog' ? 'active' : ''}`}
            onClick={() => setCurrentTab('blog')}
          >
            <i className="fas fa-blog"></i>
            Blog
          </button>
        </div>
      </nav>

      <main className="main-content">
        {renderTab()}
      </main>

      <footer className="footer">
        <p>&copy; 2024 Rio-Industry. The ultimate file management solution you'll love! 💖</p>
      </footer>
    </div>
  )
}

export default App