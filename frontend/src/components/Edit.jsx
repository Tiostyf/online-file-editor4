import React, { useState, useRef, useEffect } from 'react';
import './Edit.css';
import api from '../api';
import confetti from 'canvas-confetti';

const Edit = ({ isLoggedIn }) => {
  const [activeTool, setActiveTool] = useState('compress');
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [results, setResults] = useState([]);
  const [previewFile, setPreviewFile] = useState(null);
  const [compressLevel, setCompressLevel] = useState(75);
  const [convertFormat, setConvertFormat] = useState('jpg');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [darkMode, setDarkMode] = useState(false);
  const [draggedIndex, setDraggedIndex] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);
  const sectionsRef = useRef({});

  const tools = [
    { id: 'compress', label: 'Compress', icon: 'compact-disc', color: '#ff6b6b' },
    { id: 'merge', label: 'Merge PDFs', icon: 'layer-group', color: '#4ecdc4' },
    { id: 'convert', label: 'Convert', icon: 'exchange-alt', color: '#45b7d1' },
    { id: 'preview', label: 'Preview', icon: 'eye', color: '#96ceb4' },
    { id: 'enhance', label: 'AI Enhance', icon: 'magic', color: '#feca57' },
  ];

  useEffect(() => {
    document.body.classList.toggle('dark-mode', darkMode);
  }, [darkMode]);

  // === File Handling ===
  const handleFiles = (newFiles) => {
    const processed = newFiles.map(file => ({
      id: `${file.name}-${Date.now()}-${Math.random()}`,
      file,
      name: file.name,
      size: file.size,
      type: file.type || getFileType(file.name),
      url: URL.createObjectURL(file),
    }));
    setFiles(prev => [...prev, ...processed]);
    setError(null);
  };

  const getFileType = (name) => {
    const ext = name.split('.').pop().toLowerCase();
    const map = {
      pdf: 'application/pdf', 
      docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
      zip: 'application/zip',
      jpg: 'image/jpeg', 
      jpeg: 'image/jpeg', 
      png: 'image/png', 
      webp: 'image/webp',
      mp3: 'audio/mpeg', 
      wav: 'audio/wav',
      mp4: 'video/mp4'
    };
    return map[ext] || 'application/octet-stream';
  };

  const removeFile = (id) => {
    const file = files.find(f => f.id === id);
    if (file) URL.revokeObjectURL(file.url);
    setFiles(prev => prev.filter(f => f.id !== id));
  };

  const clearAll = () => {
    files.forEach(f => URL.revokeObjectURL(f.url));
    setFiles([]);
    setResults([]);
    setUploadProgress(0);
    setError(null);
  };

  // === Drag & Drop ===
  const handleDrop = (e) => {
    e.preventDefault();
    handleFiles(Array.from(e.dataTransfer.files));
  };

  // === Drag to Reorder (for Merge) ===
  const onDragStart = (e, index) => {
    setDraggedIndex(index);
    e.dataTransfer.effectAllowed = 'move';
  };

  const onDragOver = (e, index) => {
    e.preventDefault();
    if (draggedIndex === null) return;
    
    // Only update if position actually changed
    if (draggedIndex !== index) {
      const dragged = files[draggedIndex];
      const newFiles = [...files];
      newFiles.splice(draggedIndex, 1);
      newFiles.splice(index, 0, dragged);
      setFiles(newFiles);
      setDraggedIndex(index);
    }
  };

  const onDragEnd = () => setDraggedIndex(null);

  // === Process Files - CORRECTED VERSION ===
  const processFiles = async () => {
    if (!isLoggedIn) {
      setError('Please login to process files');
      return;
    }
    
    if (files.length === 0) {
      setError('Please select files first');
      return;
    }

    // Tool-specific validation
    if (activeTool === 'merge' && files.length < 2) {
      setError('Merge requires at least 2 files');
      return;
    }

    if (['convert', 'enhance'].includes(activeTool) && files.length !== 1) {
      setError(`${activeTool} requires exactly 1 file`);
      return;
    }

    if (activeTool === 'merge' && !files.every(f => f.type === 'application/pdf')) {
      setError('Merge only works with PDF files');
      return;
    }

    if (activeTool === 'enhance' && !files[0]?.type.startsWith('image/')) {
      setError('Enhance only works with image files');
      return;
    }

    setUploading(true);
    setUploadProgress(0);
    setResults([]);
    setError(null);

    try {
      const options = {};
      
      if (activeTool === 'compress') {
        options.compressLevel = parseInt(compressLevel);
      }
      
      if (activeTool === 'convert') {
        options.format = convertFormat;
      }

      if (activeTool === 'merge') {
        options.order = files.map(f => f.name);
      }

      console.log('Processing files with options:', { 
        tool: activeTool, 
        fileCount: files.length,
        options 
      });

      // Call the API - handle both array and single result
      const result = await api.processFiles(
        files.map(f => f.file),
        activeTool,
        options,
        (progress) => setUploadProgress(progress)
      );

      console.log('API Response:', result);

      // Handle different response formats
      let processedResults = [];
      
      if (Array.isArray(result)) {
        // If API returns array
        processedResults = result;
      } else if (result && typeof result === 'object') {
        // If API returns single object
        processedResults = [result];
      } else {
        throw new Error('Invalid response from server');
      }

      setResults(processedResults);
      
      // Check if any operation was successful
      const hasSuccess = processedResults.some(r => r && r.success);
      
      if (hasSuccess) {
        confetti({
          particleCount: 120,
          spread: 70,
          origin: { y: 0.6 },
          colors: ['#ff6b6b', '#4ecdc4', '#45b7d1', '#feca57', '#96ceb4']
        });
      } else {
        // If all failed, show the first error
        const firstError = processedResults.find(r => r && r.message)?.message || 'Processing failed';
        setError(firstError);
      }
      
    } catch (err) {
      console.error('Processing error:', err);
      const errorMessage = err.message || 'Failed to process files. Please try again.';
      setError(errorMessage);
      setResults([{ 
        success: false, 
        message: errorMessage,
        fileName: files[0]?.name || 'Unknown file'
      }]);
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  // === Preview ===
  const openPreview = (file) => setPreviewFile(file);

  // === Download - CORRECTED ===
  const downloadResultFile = (result) => {
    if (!result.url) {
      setError('Download URL not available');
      return;
    }

    try {
      // For external URLs, open in new tab
      if (result.url.startsWith('http')) {
        window.open(result.url, '_blank');
      } else {
        // For relative URLs, create download link
        const a = document.createElement('a');
        a.href = result.url;
        a.download = result.fileName || 'download';
        a.target = '_blank';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      }
    } catch (err) {
      console.error('Download error:', err);
      setError('Failed to download file');
    }
  };

  // === Scroll to Section ===
  const scrollToTool = (toolId) => {
    sectionsRef.current[toolId]?.scrollIntoView({ behavior: 'smooth' });
    setActiveTool(toolId);
    setError(null);
  };

  return (
    <div className={`edit-canvas ${darkMode ? 'dark' : ''}`}>
      {/* Floating Action Button */}
      <button className="fab" onClick={() => fileInputRef.current?.click()}>
        <i className="fas fa-plus"></i>
      </button>

      {/* Theme Toggle */}
      <button className="theme-toggle" onClick={() => setDarkMode(!darkMode)}>
        <i className={`fas ${darkMode ? 'fa-sun' : 'fa-moon'}`}></i>
      </button>

      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={(e) => {
          if (e.target.files.length > 0) {
            handleFiles(Array.from(e.target.files));
          }
        }}
        className="hidden-input"
      />

      {/* Hero Header */}
      <section className="hero">
        <div className="hero-content">
          <h1>
            <span className="gradient-text">File</span> Studio
            <span className="premium-badge">Premium</span>
          </h1>
          <p>Compress • Merge • Convert • Enhance — Like Canva, but for files</p>
          <div className="tool-switcher">
            {tools.map(t => (
              <button
                key={t.id}
                className={`tool-btn ${activeTool === t.id ? 'active' : ''}`}
                onClick={() => scrollToTool(t.id)}
                style={{ '--tool-color': t.color }}
              >
                <i className={`fas fa-${t.icon}`}></i>
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Upload Zone */}
      <section className="upload-zone" onDrop={handleDrop} onDragOver={(e) => e.preventDefault()}>
        <div className="upload-card">
          <i className="fas fa-cloud-upload-alt"></i>
          <h3>Drop files here or click +</h3>
          <p>Supports all formats • Up to 2GB • AI-powered</p>
        </div>
      </section>

      {/* Error Display */}
      {error && (
        <div className="error-banner">
          <i className="fas fa-exclamation-triangle"></i>
          <span>{error}</span>
          <button onClick={() => setError(null)} className="error-close">
            <i className="fas fa-times"></i>
          </button>
        </div>
      )}

      {/* Files Grid */}
      {files.length > 0 && (
        <section className="files-section">
          <div className="section-header">
            <h2>Your Files ({files.length})</h2>
            <button className="clear-btn" onClick={clearAll}>
              <i className="fas fa-trash"></i> Clear All
            </button>
          </div>
          <div className="files-grid">
            {files.map((f, i) => (
              <div
                key={f.id}
                className={`file-card ${draggedIndex === i ? 'dragging' : ''}`}
                draggable={activeTool === 'merge'}
                onDragStart={(e) => activeTool === 'merge' && onDragStart(e, i)}
                onDragOver={(e) => activeTool === 'merge' && onDragOver(e, i)}
                onDragEnd={onDragEnd}
              >
                <div className="file-thumb">
                  {f.type.includes('image') ? (
                    <img src={f.url} alt={f.name} />
                  ) : (
                    <i className={`fas fa-file${getFileIcon(f.type, f.name)}`}></i>
                  )}
                </div>
                <div className="file-info">
                  <p className="file-name">{f.name}</p>
                  <p className="file-size">{(f.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                <div className="file-actions">
                  <button onClick={() => openPreview(f)} title="Preview">
                    <i className="fas fa-eye"></i>
                  </button>
                  <button onClick={() => downloadResultFile({ url: f.url, fileName: f.name })} title="Download">
                    <i className="fas fa-download"></i>
                  </button>
                  <button onClick={() => removeFile(f.id)} title="Remove">
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                {uploading && (
                  <div className="progress-ring">
                    <svg>
                      <circle cx="24" cy="24" r="22" className="bg" />
                      <circle cx="24" cy="24" r="22" className="progress" style={{
                        strokeDashoffset: 138 - (138 * uploadProgress) / 100
                      }} />
                    </svg>
                    <span>{uploadProgress}%</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Tool Sections */}
      {tools.map(tool => (
        <section
          key={tool.id}
          ref={el => sectionsRef.current[tool.id] = el}
          className={`tool-section ${activeTool === tool.id ? 'active' : ''}`}
          style={{ '--tool-color': tool.color }}
        >
          <div className="tool-header">
            <div className="tool-icon">
              <i className={`fas fa-${tool.icon}`}></i>
            </div>
            <div>
              <h2>{tool.label}</h2>
              <p>{getToolDescription(tool.id)}</p>
            </div>
          </div>

          <div className="tool-content">
            {renderToolContent(tool.id, tool.color)}
          </div>

          <button 
            className={`process-btn ${uploading ? 'processing' : ''}`} 
            onClick={processFiles} 
            disabled={uploading || files.length === 0 || !isLoggedIn}
          >
            {uploading ? (
              <>
                <div className="spinner"></div>
                Processing... {uploadProgress}%
              </>
            ) : !isLoggedIn ? (
              'Please Login to Process'
            ) : (
              `Start ${tool.label}`
            )}
          </button>
        </section>
      ))}

      {/* Results */}
      {results.length > 0 && (
        <section className="results-section">
          <h2>Processing Results</h2>
          <div className="results-grid">
            {results.map((r, i) => (
              <div key={i} className={`result-card ${r.success ? 'success' : 'error'}`}>
                <i className={r.success ? 'fas fa-check-circle' : 'fas fa-exclamation-circle'}></i>
                <div className="result-info">
                  <p className="result-file"><strong>{r.fileName || 'Unknown file'}</strong></p>
                  <p className="result-message">{r.success ? 'Processing completed successfully!' : r.message}</p>
                  {r.success && r.size && (
                    <p className="file-stats">
                      Size: {(r.size / 1024 / 1024).toFixed(2)} MB
                      {r.savings && (
                        <span className="savings">
                          (Saved {(r.savings / 1024 / 1024).toFixed(2)} MB)
                        </span>
                      )}
                    </p>
                  )}
                </div>
                {r.success && r.url && (
                  <button 
                    className="download-btn" 
                    onClick={() => downloadResultFile(r)}
                    title="Download processed file"
                  >
                    <i className="fas fa-download"></i>
                  </button>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Preview Modal */}
      {previewFile && (
        <div className="modal" onClick={() => setPreviewFile(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <button className="close-modal" onClick={() => setPreviewFile(null)}>
              <i className="fas fa-times"></i>
            </button>
            <div className="preview-container">
              {renderPreview(previewFile)}
            </div>
            <div className="modal-footer">
              <button onClick={() => downloadResultFile({ url: previewFile.url, fileName: previewFile.name })}>
                <i className="fas fa-download"></i> Download Original
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  function getFileIcon(type, name) {
    const ext = name.split('.').pop().toLowerCase();
    const icons = {
      pdf: '-pdf', 
      docx: '-word', 
      xlsx: '-excel', 
      pptx: '-powerpoint',
      zip: '-archive', 
      mp3: '-audio', 
      mp4: '-video',
      jpg: '-image',
      jpeg: '-image',
      png: '-image',
      webp: '-image'
    };
    return icons[ext] || '';
  }

  function getToolDescription(id) {
    const desc = {
      compress: 'Reduce file size up to 90% with smart compression',
      merge: 'Drag to reorder and combine multiple PDFs perfectly',
      convert: 'Transform files to different formats with one click',
      preview: 'Instant preview for images, PDFs, and documents',
      enhance: 'Auto-enhance: fix lighting, sharpness, and quality',
    };
    return desc[id];
  }

  function renderToolContent(id, color) {
    switch (id) {
      case 'compress':
        return (
          <div className="slider-control">
            <label>Compression Level</label>
            <input
              type="range"
              min="10" 
              max="90"
              value={compressLevel}
              onChange={e => setCompressLevel(parseInt(e.target.value))}
              className="canva-slider"
              style={{ '--slider-color': color }}
            />
            <div className="slider-value">
              {compressLevel >= 70 ? 'High Quality' : 
               compressLevel >= 40 ? 'Balanced' : 'Maximum Compression'}
            </div>
          </div>
        );
      case 'convert':
        return (
          <div className="format-selector">
            <label>Output Format</label>
            <select 
              value={convertFormat} 
              onChange={e => setConvertFormat(e.target.value)} 
              className="canva-select"
            >
              <option value="jpg">JPG Image</option>
              <option value="png">PNG Image</option>
              <option value="webp">WebP Image</option>
              <option value="pdf">PDF Document</option>
              <option value="mp3">MP3 Audio</option>
              <option value="wav">WAV Audio</option>
            </select>
          </div>
        );
      case 'merge':
        return files.length > 1 ? (
          <div className="merge-info">
            <p className="info-text">
              <i className="fas fa-info-circle"></i>
              Drag files to reorder • Top file will be first in merged PDF
            </p>
          </div>
        ) : (
          <p className="info-text">Upload 2+ PDFs to enable merge</p>
        );
      case 'enhance':
        return files.length === 1 ? (
          <div className="enhance-options">
            <p className="info-text">
              <i className="fas fa-wand-magic-sparkles"></i>
              AI will automatically enhance brightness, contrast, and sharpness
            </p>
          </div>
        ) : (
          <p className="info-text">Select one image to enhance</p>
        );
      default:
        return <p className="info-text">Select files and click Start {id}</p>;
    }
  }

  function renderPreview(file) {
    if (file.type.includes('image')) {
      return <img src={file.url} alt="preview" className="preview-image" />;
    }
    if (file.type === 'application/pdf') {
      return (
        <div className="pdf-preview">
          <iframe src={file.url} title="PDF Preview" className="preview-iframe" />
        </div>
      );
    }
    if (file.type.includes('audio')) {
      return (
        <div className="audio-preview">
          <audio controls src={file.url} className="preview-audio" />
        </div>
      );
    }
    if (file.type.includes('video')) {
      return <video controls src={file.url} className="preview-video" />;
    }
    return (
      <div className="preview-fallback">
        <i className="fas fa-file"></i>
        <p>Preview not available for this file type</p>
      </div>
    );
  }
};

export default Edit;