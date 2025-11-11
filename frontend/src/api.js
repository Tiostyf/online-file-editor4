// src/api.js
const API_BASE = import.meta.env.VITE_API_URL || 'https://online-file-editor4.onrender.com';

const TOKEN_KEY = 'auth_token';

// Improved token handling
const getToken = () => {
  const token = localStorage.getItem(TOKEN_KEY);
  // Validate token before returning
  if (!token || token === 'null' || token === 'undefined' || token.trim() === '') {
    console.warn('Invalid token found in storage');
    localStorage.removeItem(TOKEN_KEY);
    return null;
  }
  return token;
};

const setToken = (token) => {
  if (!token || token === 'null' || token === 'undefined') {
    console.error('Attempt to set invalid token');
    localStorage.removeItem(TOKEN_KEY);
    return;
  }
  
  // Basic JWT validation
  const tokenParts = token.split('.');
  if (tokenParts.length !== 3) {
    console.error('Invalid JWT format, not storing');
    return;
  }
  
  localStorage.setItem(TOKEN_KEY, token);
};

const clearToken = () => {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem('user_data');
};

const authHeaders = () => {
  const token = getToken();
  if (!token) {
    return {};
  }
  
  return { 
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };
};

// Safely parse JSON
const safeJsonParse = (text) => {
  try {
    return text?.trim() ? JSON.parse(text) : {};
  } catch (err) {
    console.warn('Invalid JSON:', text);
    return {};
  }
};

// Handle fetch responses with better error handling
const handleResponse = async (res) => {
  const text = await res.text();
  const data = safeJsonParse(text);
  
  if (!res.ok) {
    // Handle specific HTTP status codes
    if (res.status === 401) {
      clearToken();
      throw new Error('Session expired. Please login again.');
    } else if (res.status === 403) {
      throw new Error('Access denied');
    } else if (res.status === 404) {
      throw new Error('Resource not found');
    } else if (res.status >= 500) {
      throw new Error('Server error. Please try again later.');
    }
    
    throw new Error(data.message || data.error || `HTTP ${res.status}`);
  }
  
  return data;
};

// Enhanced fetch with timeout
const fetchWithTimeout = (url, options = {}, timeout = 30000) => {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Request timeout')), timeout)
    )
  ]);
};

// === AUTH ===
export const login = async (email, password) => {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await handleResponse(res);
    
    if (data.success && data.token) {
      setToken(data.token);
      // Store user data for quick access
      if (data.user) {
        localStorage.setItem('user_data', JSON.stringify(data.user));
      }
      return { success: true, user: data.user };
    }
    
    throw new Error(data.message || 'Login failed');
  } catch (error) {
    clearToken();
    throw error;
  }
};

export const register = async (username, email, password, fullName = '', company = '') => {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, fullName, company })
    });
    
    const data = await handleResponse(res);
    
    if (data.success && data.token) {
      setToken(data.token);
      if (data.user) {
        localStorage.setItem('user_data', JSON.stringify(data.user));
      }
      return { success: true, user: data.user };
    }
    
    throw new Error(data.message || 'Registration failed');
  } catch (error) {
    clearToken();
    throw error;
  }
};

export const logout = () => {
  clearToken();
  return Promise.resolve();
};

export const isLoggedIn = () => {
  const token = getToken();
  if (!token) return false;
  
  // Basic token expiration check (optional)
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      clearToken();
      return false;
    }
    return true;
  } catch {
    return false;
  }
};

// Get current user from localStorage (fast)
export const getCurrentUser = () => {
  try {
    const userData = localStorage.getItem('user_data');
    return userData ? JSON.parse(userData) : null;
  } catch {
    return null;
  }
};

// === PROFILE ===
export const fetchProfile = async () => {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/profile`, { 
      headers: authHeaders() 
    });
    
    const data = await handleResponse(res);
    
    if (data.success && data.user) {
      // Update stored user data
      localStorage.setItem('user_data', JSON.stringify(data.user));
      return data.user;
    }
    
    throw new Error(data.message || 'Failed to fetch profile');
  } catch (error) {
    if (error.message.includes('Session expired')) {
      clearToken();
    }
    throw error;
  }
};

export const updateProfile = async (updates) => {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/profile`, {
      method: 'PUT',
      headers: authHeaders(),
      body: JSON.stringify(updates)
    });
    
    const data = await handleResponse(res);
    
    if (data.success && data.user) {
      localStorage.setItem('user_data', JSON.stringify(data.user));
      return data.user;
    }
    
    throw new Error(data.message || 'Profile update failed');
  } catch (error) {
    throw error;
  }
};

// === PROCESS FILES ===
export const processFiles = async (files, tool, options = {}, onProgress = () => {}) => {
  // Validate input
  if (!files?.length) throw new Error('No files selected');
  
  const validTools = ['compress', 'merge', 'convert', 'enhance', 'preview'];
  if (!validTools.includes(tool)) {
    throw new Error(`Invalid tool: ${tool}. Valid tools are: ${validTools.join(', ')}`);
  }

  // File count rules
  if (tool === 'merge' && files.length < 2) throw new Error('Merge requires at least 2 files');
  if (['convert', 'enhance'].includes(tool) && files.length !== 1) {
    throw new Error(`${tool} requires exactly 1 file`);
  }

  const form = new FormData();
  
  // Use 'files' as field name to match server
  files.forEach(file => form.append('files', file));
  
  form.append('tool', tool);

  // Compression level
  if (tool === 'compress') {
    const level = options.compressLevel 
      ? Math.max(1, Math.min(9, Math.round(options.compressLevel / 10)))
      : 6;
    form.append('compressLevel', level.toString());
  }

  // Merge order
  if (tool === 'merge' && options.order) {
    form.append('order', JSON.stringify(options.order));
  }

  // Convert format
  if (tool === 'convert' && options.format) {
    const ext = options.format.toLowerCase();
    const validFormats = ['jpg', 'jpeg', 'png', 'webp', 'mp3', 'wav', 'pdf'];
    if (!validFormats.includes(ext)) {
      throw new Error(`Unsupported format: ${options.format}. Use: ${validFormats.join(', ')}`);
    }
    form.append('format', ext);
  }

  // Enhance validation
  if (tool === 'enhance' && files[0] && !files[0].type.startsWith('image/')) {
    throw new Error('Only images can be enhanced');
  }

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API_BASE}/api/process`);
    xhr.timeout = 300000; // 5 minutes timeout for large files

    const token = getToken();
    if (token) {
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    }

    // Upload progress
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = Math.round((e.loaded / e.total) * 100);
        onProgress(percent, 'upload');
      }
    };

    // Download progress (for processing)
    xhr.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = Math.round((e.loaded / e.total) * 100);
        onProgress(percent, 'process');
      }
    };

    xhr.onload = () => {
      try {
        const data = safeJsonParse(xhr.responseText);

        if (xhr.status === 200 && data.success) {
          // Handle preview tool response differently
          if (tool === 'preview') {
            resolve({
              success: true,
              files: data.files,
              message: data.message,
              tool: 'preview'
            });
          } else {
            // Ensure URL is absolute
            let fileUrl = data.url || data.data?.url;
            if (fileUrl && !fileUrl.startsWith('http')) {
              fileUrl = `${API_BASE}${fileUrl}`;
            }
            
            resolve({
              success: true,
              url: fileUrl,
              downloadUrl: data.data?.downloadUrl || fileUrl,
              fileName: data.fileName || data.data?.fileName,
              size: data.size || data.data?.size,
              originalSize: data.originalSize || data.data?.originalSize,
              savings: data.savings || data.data?.savings,
              compressionRatio: data.compressionRatio || data.data?.compressionRatio,
              tool: data.tool || tool,
              fileId: data.data?.fileId,
              message: data.message
            });
          }
        } else {
          const errorMsg = data.message || data.error || `Server error: ${xhr.status}`;
          reject(new Error(errorMsg));
        }
      } catch (parseError) {
        reject(new Error('Failed to parse server response'));
      }
    };

    xhr.onerror = () => reject(new Error('Network error - please check your connection'));
    xhr.ontimeout = () => reject(new Error('Request timeout - server is taking too long to respond'));
    xhr.onabort = () => reject(new Error('Request cancelled'));

    xhr.send(form);
  });
};

// === HISTORY ===
export const getHistory = async (page = 1, limit = 10) => {
  try {
    const res = await fetchWithTimeout(
      `${API_BASE}/api/history?page=${page}&limit=${limit}`, 
      { headers: authHeaders() }
    );
    
    const data = await handleResponse(res);
    
    if (data.success) {
      return { 
        files: data.files || data.data?.files || [], 
        total: data.total || data.data?.pagination?.total || 0, 
        page: data.page || data.data?.pagination?.page || page, 
        pages: data.pages || data.data?.pagination?.pages || 1,
        pagination: data.data?.pagination
      };
    }
    
    throw new Error(data.message || 'Failed to fetch history');
  } catch (error) {
    throw error;
  }
};

// === DOWNLOAD FILE ===
export const downloadFile = (filename, fileId = null) => {
  const token = getToken();
  let url = `${API_BASE}/api/download/${encodeURIComponent(filename)}`;
  
  // Add token as query parameter for better compatibility
  if (token) {
    url += `?token=${token}`;
    if (fileId) {
      url += `&fileId=${fileId}`;
    }
  }
  
  // Create a temporary anchor to trigger download
  const link = document.createElement('a');
  link.href = url;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.click();
};

// Alternative download method using fetch
export const downloadFileDirect = async (filename) => {
  try {
    const res = await fetchWithTimeout(
      `${API_BASE}/api/download/${encodeURIComponent(filename)}`,
      { headers: authHeaders() }
    );
    
    if (!res.ok) {
      throw new Error(`Download failed: ${res.status}`);
    }
    
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
    
    return { success: true };
  } catch (error) {
    throw error;
  }
};

// === HEALTH CHECK ===
export const checkHealth = async () => {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/health`, {}, 10000);
    const data = await handleResponse(res);
    return { 
      ok: true, 
      data,
      database: data.database?.status === 'Connected'
    };
  } catch (error) {
    return { 
      ok: false, 
      error: error.message,
      database: false
    };
  }
};

// === DATABASE STATUS ===
export const checkDatabaseStatus = async () => {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/diagnostics`, { 
      headers: authHeaders() 
    });
    const data = await handleResponse(res);
    return { success: true, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// === FILE MANAGEMENT ===
export const deleteFile = async (fileId) => {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/files/${fileId}`, {
      method: 'DELETE',
      headers: authHeaders()
    });
    
    const data = await handleResponse(res);
    
    if (data.success) {
      return { success: true, message: data.message };
    }
    
    throw new Error(data.message || 'Failed to delete file');
  } catch (error) {
    throw error;
  }
};

// === UTILITY FUNCTIONS ===
export const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const calculateSavings = (originalSize, compressedSize) => {
  if (!originalSize || !compressedSize) return 0;
  return Math.max(0, originalSize - compressedSize);
};

export const calculateCompressionRatio = (originalSize, compressedSize) => {
  if (!originalSize || originalSize === 0) return 0;
  return Math.round(((originalSize - compressedSize) / originalSize) * 100);
};

// === EXPORT ALL ===
export default {
  login,
  register,
  logout,
  isLoggedIn,
  getCurrentUser,
  fetchProfile,
  updateProfile,
  processFiles,
  getHistory,
  downloadFile,
  downloadFileDirect,
  deleteFile,
  checkHealth,
  checkDatabaseStatus,
  formatFileSize,
  calculateSavings,
  calculateCompressionRatio
};