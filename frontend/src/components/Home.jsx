import React from 'react'
import './Home.css'

const Home = () => {
  const features = [
    {
      icon: 'fas fa-bolt',
      title: 'Lightning Fast Processing',
      description: 'Experience blazing-fast file compression with our optimized algorithms that reduce processing time by 70% compared to traditional methods.'
    },
    {
      icon: 'fas fa-shield-alt',
      title: 'Military-Grade Security',
      description: 'Your files are protected with AES-256 encryption during transfer and storage. We never store your passwords or sensitive data.'
    },
    {
      icon: 'fas fa-cloud-upload-alt',
      title: 'Smart Cloud Integration',
      description: 'Seamlessly sync with Google Drive, Dropbox, and OneCloud. Automatic backup ensures you never lose important files.'
    },
    {
      icon: 'fas fa-robot',
      title: 'AI-Powered Optimization',
      description: 'Our intelligent system analyzes file types and applies the best compression method automatically for maximum efficiency.'
    },
    {
      icon: 'fas fa-mobile-alt',
      title: 'Cross-Platform Compatibility',
      description: 'Access your files from any device - desktop, tablet, or mobile. Fully responsive design adapts to your screen size.'
    },
    {
      icon: 'fas fa-chart-line',
      title: 'Advanced Analytics',
      description: 'Track your storage savings with detailed reports and visual analytics. Monitor trends and optimize your file management strategy.'
    },
    {
      icon: 'fas fa-users',
      title: 'Team Collaboration',
      description: 'Share compressed files with team members securely. Real-time collaboration features enhance productivity across organizations.'
    },
    {
      icon: 'fas fa-infinity',
      title: 'Unlimited File Types',
      description: 'Support for 200+ file formats including documents, images, videos, audio files, and specialized professional formats.'
    },
    {
      icon: 'fas fa-rocket',
      title: 'Batch Processing',
      description: 'Compress multiple files simultaneously with our advanced batch processing feature. Save hours of manual work.'
    },
    {
      icon: 'fas fa-star',
      title: 'Premium Support',
      description: '24/7 customer support with average response time under 2 minutes. Dedicated account managers for enterprise clients.'
    }
  ]

  return (
    <div className="home">
      <section className="hero">
        <div className="hero-content">
          <h1>Welcome to Rio-Industry</h1>
          <p className="hero-subtitle">The Ultimate File Management Solution You'll Absolutely Love! 💖</p>
          <p className="hero-description">
            Transform your digital workflow with our powerful, intuitive, and feature-rich file management platform. 
            Experience the future of file compression and organization today.
          </p>
          <div className="hero-stats">
            <div className="stat">
              <i className="fas fa-users"></i>
              <span>50K+ Happy Users</span>
            </div>
            <div className="stat">
              <i className="fas fa-file-archive"></i>
              <span>2M+ Files Compressed</span>
            </div>
            <div className="stat">
              <i className="fas fa-cloud"></i>
              <span>500TB+ Space Saved</span>
            </div>
          </div>
        </div>
        <div className="hero-visual">
          <i className="fas fa-cloud-upload-alt"></i>
        </div>
      </section>

      <section className="features-grid">
        <h2>Why You'll Love FileMaster Pro</h2>
        <div className="features-container">
          {features.map((feature, index) => (
            <div key={index} className="feature-card">
              <div className="feature-icon">
                <i className={feature.icon}></i>
              </div>
              <h3>{feature.title}</h3>
              <p>{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="cta-section">
        <div className="cta-content">
          <h2>Ready to Transform Your File Management?</h2>
          <p>Join thousands of satisfied users who have revolutionized their digital workflow</p>
          <button className="cta-button">
            <i className="fas fa-rocket"></i>
            Get Started Free
          </button>
        </div>
      </section>
    </div>
  )
}

export default Home