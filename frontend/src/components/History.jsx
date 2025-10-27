import React, { useState, useEffect } from 'react'
import './History.css'
import api from '../api'

const History = ({ isLoggedIn }) => {
  const [activeFilter, setActiveFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [historyData, setHistoryData] = useState([])
  const [loading, setLoading] = useState(true)
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [stats, setStats] = useState({
    totalFiles: 0,
    totalSavings: '0 MB',
    averageSavings: '0%',
    mostProcessed: 'None'
  })

  const historyFeatures = [
    {
      icon: 'fas fa-chart-line',
      title: 'Detailed Analytics',
      description: 'Comprehensive analytics dashboard showing compression ratios, storage savings, and performance metrics over time with interactive charts.'
    },
    {
      icon: 'fas fa-filter',
      title: 'Smart Filtering',
      description: 'Advanced filtering options by date range, file type, action type, and size. Save custom filters for quick access to frequently used views.'
    },
    {
      icon: 'fas fa-search',
      title: 'Powerful Search',
      description: 'Real-time search across all historical data with fuzzy matching and keyword highlighting. Search by filename, content, or metadata.'
    },
    {
      icon: 'fas fa-download',
      title: 'Export Capabilities',
      description: 'Export your history data in multiple formats (CSV, JSON, PDF). Schedule automated reports and share insights with team members.'
    },
    {
      icon: 'fas fa-sync',
      title: 'Auto-Sync',
      description: 'Automatic synchronization across all your devices. Real-time updates ensure your history is always current and accessible anywhere.'
    },
    {
      icon: 'fas fa-trash-restore',
      title: 'Recovery Options',
      description: 'One-click restoration of previous file versions. Complete audit trail with ability to revert any action taken on your files.'
    },
    {
      icon: 'fas fa-shield-alt',
      title: 'Privacy Controls',
      description: 'Granular privacy settings with the ability to hide specific files or actions. End-to-end encryption for sensitive historical data.'
    },
    {
      icon: 'fas fa-bell',
      title: 'Smart Notifications',
      description: 'Customizable alerts for important events. Get notified about storage milestones, unusual activity, or completion of batch processes.'
    },
    {
      icon: 'fas fa-users',
      title: 'Team History',
      description: 'Collaborative history tracking for teams. Monitor team activity, track shared file changes, and maintain organizational transparency.'
    },
    {
      icon: 'fas fa-infinity',
      title: 'Unlimited History',
      description: 'Never lose track of your file operations. Unlimited history storage with fast retrieval and advanced archiving capabilities.'
    }
  ]

  // Fetch user history from API
  useEffect(() => {
    if (isLoggedIn) {
      fetchHistory()
      fetchUserStats()
    }
  }, [isLoggedIn, currentPage])

  const fetchHistory = async () => {
    try {
      setLoading(true)
      const response = await api.getHistory(currentPage)
      if (response && response.files) {
        setHistoryData(response.files)
        setTotalPages(response.pages || 1)
      }
    } catch (error) {
      console.error('Error fetching history:', error)
      setHistoryData([])
    } finally {
      setLoading(false)
    }
  }

  const fetchUserStats = async () => {
    try {
      const userProfile = await api.fetchProfile()
      if (userProfile && userProfile.stats) {
        const userStats = userProfile.stats
        setStats({
          totalFiles: userStats.totalFiles || 0,
          totalSavings: formatBytes(userStats.spaceSaved || 0),
          averageSavings: calculateAverageSavings(userStats),
          mostProcessed: getMostProcessedType(historyData)
        })
      }
    } catch (error) {
      console.error('Error fetching user stats:', error)
    }
  }

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const calculateAverageSavings = (userStats) => {
    if (!userStats.totalSize || userStats.totalSize === 0) return '0%'
    const savingsRatio = (userStats.spaceSaved / userStats.totalSize) * 100
    return savingsRatio.toFixed(1) + '%'
  }

  const getMostProcessedType = (files) => {
    if (!files.length) return 'None'
    
    const typeCount = {}
    files.forEach(file => {
      const type = getFileType(file.originalName || file.filename)
      typeCount[type] = (typeCount[type] || 0) + 1
    })
    
    const mostCommon = Object.keys(typeCount).reduce((a, b) => 
      typeCount[a] > typeCount[b] ? a : b
    )
    
    return mostCommon
  }

  const getFileType = (filename) => {
    const ext = filename.split('.').pop().toLowerCase()
    const typeMap = {
      'pdf': 'document',
      'doc': 'document',
      'docx': 'document',
      'txt': 'document',
      'zip': 'archive',
      'rar': 'archive',
      '7z': 'archive',
      'ppt': 'presentation',
      'pptx': 'presentation',
      'jpg': 'image',
      'jpeg': 'image',
      'png': 'image',
      'webp': 'image',
      'mp3': 'audio',
      'wav': 'audio',
      'mp4': 'video',
      'avi': 'video',
      'sql': 'database',
      'csv': 'database'
    }
    return typeMap[ext] || 'other'
  }

  const getFileIcon = (filename) => {
    const type = getFileType(filename)
    const iconMap = {
      'document': 'file-pdf',
      'archive': 'file-archive',
      'presentation': 'file-powerpoint',
      'image': 'file-image',
      'audio': 'file-audio',
      'video': 'file-video',
      'database': 'file-code',
      'other': 'file'
    }
    return iconMap[type] || 'file'
  }

  const getActionType = (toolUsed) => {
    const actionMap = {
      'compress': 'compressed',
      'merge': 'merged',
      'convert': 'converted',
      'enhance': 'enhanced'
    }
    return actionMap[toolUsed] || 'processed'
  }

  const getActionColor = (action) => {
    const colorMap = {
      'compressed': 'compressed',
      'merged': 'converted',
      'converted': 'converted',
      'enhanced': 'encrypted'
    }
    return colorMap[action] || 'converted'
  }

  const formatDate = (dateString) => {
    const date = new Date(dateString)
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  const calculateSavingsPercentage = (file) => {
    if (!file.size || !file.compressedSize) return '0%'
    const savings = ((file.size - file.compressedSize) / file.size) * 100
    return savings > 0 ? savings.toFixed(1) + '%' : '0%'
  }

  const filteredHistory = historyData.filter(item => {
    const matchesFilter = activeFilter === 'all' || getFileType(item.originalName || item.filename) === activeFilter
    const matchesSearch = (item.originalName || item.filename).toLowerCase().includes(searchTerm.toLowerCase())
    return matchesFilter && matchesSearch
  })

  const exportHistory = () => {
    const csvContent = [
      ['File Name', 'Action', 'Date', 'Original Size', 'Compressed Size', 'Savings', 'Status'],
      ...filteredHistory.map(item => [
        item.originalName || item.filename,
        getActionType(item.toolUsed),
        formatDate(item.createdAt),
        formatBytes(item.size),
        formatBytes(item.compressedSize),
        calculateSavingsPercentage(item),
        'completed'
      ])
    ].map(row => row.join(',')).join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `file-history-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  const clearHistory = async () => {
    if (window.confirm('Are you sure you want to clear your history? This action cannot be undone.')) {
      // Note: You'll need to add a clear history endpoint to your API
      alert('Clear history functionality would be implemented here')
    }
  }

  const handlePageChange = (newPage) => {
    setCurrentPage(newPage)
  }

  if (!isLoggedIn) {
    return (
      <div className="history">
        <div className="login-prompt">
          <i className="fas fa-history" style={{ fontSize: '4rem', marginBottom: '1rem', color: '#667eea' }}></i>
          <h2>Login to View Your History</h2>
          <p>Please log in to access your file processing history and analytics.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="history">
      <div className="history-header">
        <h1>Activity History & Analytics</h1>
        <p className="history-subtitle">Track, analyze, and manage all your file operations in one place</p>
      </div>

      <div className="history-stats">
        <div className="stat-card">
          <i className="fas fa-file-alt"></i>
          <div className="stat-info">
            <h3>{stats.totalFiles}</h3>
            <p>Files Processed</p>
          </div>
        </div>
        <div className="stat-card">
          <i className="fas fa-database"></i>
          <div className="stat-info">
            <h3>{stats.totalSavings}</h3>
            <p>Total Savings</p>
          </div>
        </div>
        <div className="stat-card">
          <i className="fas fa-chart-pie"></i>
          <div className="stat-info">
            <h3>{stats.averageSavings}</h3>
            <p>Average Savings</p>
          </div>
        </div>
        <div className="stat-card">
          <i className="fas fa-folder"></i>
          <div className="stat-info">
            <h3>{stats.mostProcessed}</h3>
            <p>Most Processed</p>
          </div>
        </div>
      </div>

      <div className="history-controls">
        <div className="search-box">
          <i className="fas fa-search"></i>
          <input
            type="text"
            placeholder="Search history..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="filter-buttons">
          {['all', 'document', 'archive', 'image', 'video', 'audio', 'other'].map(filter => (
            <button
              key={filter}
              className={`filter-btn ${activeFilter === filter ? 'active' : ''}`}
              onClick={() => setActiveFilter(filter)}
            >
              {filter.charAt(0).toUpperCase() + filter.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="history-list">
        {loading ? (
          <div className="loading-state">
            <i className="fas fa-spinner fa-spin"></i>
            <p>Loading your history...</p>
          </div>
        ) : filteredHistory.length === 0 ? (
          <div className="empty-state">
            <i className="fas fa-inbox"></i>
            <h3>No History Found</h3>
            <p>Your file processing history will appear here once you start using the tools.</p>
          </div>
        ) : (
          <>
            <div className="list-header">
              <span>File Name</span>
              <span>Action</span>
              <span>Date</span>
              <span>Size</span>
              <span>Savings</span>
              <span>Status</span>
            </div>
            {filteredHistory.map(item => (
              <div key={item._id || item.id} className="history-item">
                <div className="file-info">
                  <i className={`fas fa-${getFileIcon(item.originalName || item.filename)}`}></i>
                  <span className="file-name">{item.originalName || item.filename}</span>
                </div>
                <span className={`action action-${getActionColor(getActionType(item.toolUsed))}`}>
                  {getActionType(item.toolUsed)}
                </span>
                <span className="date">{formatDate(item.createdAt)}</span>
                <div className="size-comparison">
                  <span className="size-before">{formatBytes(item.size)}</span>
                  <i className="fas fa-arrow-right"></i>
                  <span className="size-after">{formatBytes(item.compressedSize)}</span>
                </div>
                <span className={`savings ${parseFloat(calculateSavingsPercentage(item)) > 0 ? 'positive' : 'neutral'}`}>
                  {calculateSavingsPercentage(item)}
                </span>
                <span className="status status-completed">
                  <i className="fas fa-check-circle"></i>
                  completed
                </span>
              </div>
            ))}
          </>
        )}
      </div>

      {totalPages > 1 && (
        <div className="pagination">
          <button 
            className="pagination-btn" 
            disabled={currentPage === 1}
            onClick={() => handlePageChange(currentPage - 1)}
          >
            <i className="fas fa-chevron-left"></i> Previous
          </button>
          <span className="pagination-info">
            Page {currentPage} of {totalPages}
          </span>
          <button 
            className="pagination-btn"
            disabled={currentPage === totalPages}
            onClick={() => handlePageChange(currentPage + 1)}
          >
            Next <i className="fas fa-chevron-right"></i>
          </button>
        </div>
      )}

      <section className="history-features">
        <h2>Advanced History Features</h2>
        <div className="features-container">
          {historyFeatures.map((feature, index) => (
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

      <div className="history-actions">
        <button className="action-btn" onClick={exportHistory}>
          <i className="fas fa-download"></i>
          Export History
        </button>
        <button className="action-btn" onClick={clearHistory}>
          <i className="fas fa-trash"></i>
          Clear History
        </button>
        <button className="action-btn primary">
          <i className="fas fa-chart-bar"></i>
          View Analytics
        </button>
      </div>
    </div>
  )
}

export default History