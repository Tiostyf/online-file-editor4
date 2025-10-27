import React, { useState } from 'react'
import './Blog.css'

const Blog = () => {
  const [activeCategory, setActiveCategory] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')

  const blogPosts = [
    {
      id: 1,
      title: 'Mastering File Compression: Advanced Techniques for 2024',
      excerpt: 'Discover the latest compression algorithms and how they can save you terabytes of storage space while maintaining file integrity.',
      author: 'Sarah Chen',
      date: '2024-01-15',
      readTime: '8 min read',
      category: 'tutorials',
      image: '📊',
      tags: ['compression', 'storage', 'optimization'],
      featured: true
    },
    {
      id: 2,
      title: 'The Future of Cloud Storage: AI-Powered Management',
      excerpt: 'How artificial intelligence is revolutionizing the way we store, organize, and access our digital files across multiple platforms.',
      author: 'Mike Rodriguez',
      date: '2024-01-12',
      readTime: '6 min read',
      category: 'technology',
      image: '🤖',
      tags: ['AI', 'cloud', 'future'],
      featured: true
    },
    {
      id: 3,
      title: 'Security Best Practices for File Sharing in 2024',
      excerpt: 'Essential security measures every professional should implement when sharing sensitive documents and media files.',
      author: 'Dr. Emily Watson',
      date: '2024-01-10',
      readTime: '10 min read',
      category: 'security',
      image: '🔒',
      tags: ['security', 'encryption', 'privacy']
    },
    {
      id: 4,
      title: 'Batch Processing: How to Handle Large File Collections',
      excerpt: 'Step-by-step guide to efficiently process thousands of files simultaneously without compromising performance.',
      author: 'Alex Thompson',
      date: '2024-01-08',
      readTime: '5 min read',
      category: 'tutorials',
      image: '⚡',
      tags: ['batch', 'efficiency', 'automation']
    },
    {
      id: 5,
      title: 'The Psychology of File Organization',
      excerpt: 'Understanding how proper file organization can boost productivity and reduce digital clutter in your workflow.',
      author: 'Dr. Lisa Park',
      date: '2024-01-05',
      readTime: '7 min read',
      category: 'productivity',
      image: '🧠',
      tags: ['organization', 'psychology', 'productivity']
    },
    {
      id: 6,
      title: 'Mobile File Management: Tips for On-the-Go Professionals',
      excerpt: 'Optimize your mobile workflow with these essential file management apps and techniques for busy professionals.',
      author: 'James Wilson',
      date: '2024-01-03',
      readTime: '4 min read',
      category: 'mobile',
      image: '📱',
      tags: ['mobile', 'apps', 'workflow']
    }
  ]

  const blogFeatures = [
    {
      icon: 'fas fa-newspaper',
      title: 'Daily Updates',
      description: 'Fresh content published daily covering the latest trends, tips, and technologies in file management and digital organization.'
    },
    {
      icon: 'fas fa-graduation-cap',
      title: 'Expert Tutorials',
      description: 'Step-by-step guides and video tutorials from industry experts. Learn advanced techniques and hidden features of file management tools.'
    },
    {
      icon: 'fas fa-chart-bar',
      title: 'Industry Insights',
      description: 'In-depth analysis of market trends, user behavior studies, and predictive analytics for the future of digital storage.'
    },
    {
      icon: 'fas fa-tools',
      title: 'Tool Reviews',
      description: 'Comprehensive reviews of the latest file management software, cloud services, and productivity tools with hands-on testing.'
    },
    {
      icon: 'fas fa-users',
      title: 'Community Spotlights',
      description: 'Featured stories from our user community. Learn how real people are solving complex file management challenges.'
    },
    {
      icon: 'fas fa-video',
      title: 'Video Content',
      description: 'Exclusive video interviews, webinars, and live demonstrations. Visual learning resources for complex topics and new features.'
    },
    {
      icon: 'fas fa-download',
      title: 'Free Resources',
      description: 'Downloadable templates, checklists, and resource kits. Practical tools you can immediately apply to improve your workflow.'
    },
    {
      icon: 'fas fa-comments',
      title: 'Interactive Discussions',
      description: 'Live Q&A sessions, comment sections, and community forums. Engage with authors and fellow readers in meaningful discussions.'
    },
    {
      icon: 'fas fa-mobile-alt',
      title: 'Mobile Optimized',
      description: 'All content optimized for mobile devices. Read on the go with our responsive design and offline reading capabilities.'
    },
    {
      icon: 'fas fa-rss',
      title: 'RSS & Newsletters',
      description: 'Stay updated with customizable RSS feeds and weekly newsletters. Get curated content delivered directly to your inbox.'
    }
  ]

  const categories = ['all', 'tutorials', 'technology', 'security', 'productivity', 'mobile']

  const filteredPosts = blogPosts.filter(post => {
    const matchesCategory = activeCategory === 'all' || post.category === activeCategory
    const matchesSearch = post.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         post.excerpt.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         post.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
    return matchesCategory && matchesSearch
  })

  const featuredPosts = blogPosts.filter(post => post.featured)

  return (
    <div className="blog">
      <div className="blog-header">
        <h1>FileMaster Pro Blog</h1>
        <p className="blog-subtitle">Insights, Tips, and Trends in File Management</p>
      </div>

      <div className="blog-hero">
        <div className="hero-content">
          <h2>Stay Ahead in Digital File Management</h2>
          <p>Expert articles, tutorials, and industry insights to help you master file compression, organization, and security</p>
          <div className="newsletter-signup">
            <input 
              type="email" 
              placeholder="Enter your email for updates..."
              className="newsletter-input"
            />
            <button className="newsletter-btn">
              <i className="fas fa-paper-plane"></i>
              Subscribe
            </button>
          </div>
        </div>
        <div className="hero-stats">
          <div className="stat">
            <strong>500+</strong>
            <span>Articles</span>
          </div>
          <div className="stat">
            <strong>50K+</strong>
            <span>Readers</span>
          </div>
          <div className="stat">
            <strong>98%</strong>
            <span>Satisfaction</span>
          </div>
        </div>
      </div>

      {featuredPosts.length > 0 && (
        <section className="featured-posts">
          <h2>Featured Articles</h2>
          <div className="featured-grid">
            {featuredPosts.map(post => (
              <div key={post.id} className="featured-card">
                <div className="post-image">
                  {post.image}
                </div>
                <div className="post-content">
                  <span className="category-tag">{post.category}</span>
                  <h3>{post.title}</h3>
                  <p>{post.excerpt}</p>
                  <div className="post-meta">
                    <span className="author">
                      <i className="fas fa-user"></i>
                      {post.author}
                    </span>
                    <span className="date">
                      <i className="fas fa-calendar"></i>
                      {post.date}
                    </span>
                    <span className="read-time">
                      <i className="fas fa-clock"></i>
                      {post.readTime}
                    </span>
                  </div>
                  <button className="read-more-btn">
                    Read Full Article
                    <i className="fas fa-arrow-right"></i>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="blog-controls">
        <div className="search-section">
          <div className="search-box">
            <i className="fas fa-search"></i>
            <input
              type="text"
              placeholder="Search articles..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
        <div className="category-filters">
          {categories.map(category => (
            <button
              key={category}
              className={`category-btn ${activeCategory === category ? 'active' : ''}`}
              onClick={() => setActiveCategory(category)}
            >
              {category.charAt(0).toUpperCase() + category.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <section className="blog-posts">
        <h2>Latest Articles</h2>
        <div className="posts-grid">
          {filteredPosts.map(post => (
            <div key={post.id} className="post-card">
              <div className="post-header">
                <div className="post-image">
                  {post.image}
                </div>
                <span className="category-tag">{post.category}</span>
              </div>
              <div className="post-content">
                <h3>{post.title}</h3>
                <p>{post.excerpt}</p>
                <div className="post-tags">
                  {post.tags.map(tag => (
                    <span key={tag} className="tag">#{tag}</span>
                  ))}
                </div>
                <div className="post-meta">
                  <div className="author-info">
                    <i className="fas fa-user"></i>
                    {post.author}
                  </div>
                  <div className="post-info">
                    <span>{post.date}</span>
                    <span>•</span>
                    <span>{post.readTime}</span>
                  </div>
                </div>
                <button className="read-btn">
                  Read More
                  <i className="fas fa-arrow-right"></i>
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="blog-features">
        <h2>Why You'll Love Our Blog</h2>
        <div className="features-container">
          {blogFeatures.map((feature, index) => (
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

      <div className="blog-cta">
        <div className="cta-content">
          <h3>Become a Contributor</h3>
          <p>Share your expertise with our community of file management enthusiasts</p>
          <button className="cta-btn">
            <i className="fas fa-edit"></i>
            Write for Us
          </button>
        </div>
      </div>
    </div>
  )
}

export default Blog