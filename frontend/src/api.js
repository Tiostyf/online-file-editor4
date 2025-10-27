// src/api.js
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5001';

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
};

const authHeaders = () => {
  const token = getToken();
  if (!token) {
    return {};
  }
  
  return { 
    Authorization: `Bearer ${token}`
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

// Handle fetch responses
const handleResponse = async (res) => {
  const text = await res.text();
  const data = safeJsonParse(text);
  if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
  return data;
};

// === AUTH ===
export const login = (email, password) =>
  fetch(`${API_BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  })
    .then(handleResponse)
    .then(data => {
      if (data.success && data.token) {
        setToken(data.token);
        return { success: true, user: data.user };
      }
      throw new Error(data.message || 'Login failed');
    })
    .catch(error => {
      clearToken();
      throw error;
    });

export const register = (username, email, password, fullName = '', company = '') =>
  fetch(`${API_BASE}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password, fullName, company })
  })
    .then(handleResponse)
    .then(data => {
      if (data.success && data.token) {
        setToken(data.token);
        return { success: true, user: data.user };
      }
      throw new Error(data.message || 'Registration failed');
    });

export const logout = () => {
  clearToken();
  return Promise.resolve();
};

export const isLoggedIn = () => !!getToken();

// === PROFILE ===
export const fetchProfile = () =>
  fetch(`${API_BASE}/api/profile`, { headers: authHeaders() })
    .then(handleResponse)
    .then(data => {
      if (data.success && data.user) return data.user;
      throw new Error(data.message || 'Failed to fetch profile');
    });

export const updateProfile = (updates) =>
  fetch(`${API_BASE}/api/profile`, {
    method: 'PUT',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  })
    .then(handleResponse)
    .then(data => {
      if (data.success && data.user) return data.user;
      throw new Error(data.message || 'Update failed');
    });

// === PROCESS FILES ===
export const processFiles = async (files, tool, options = {}, onProgress = () => {}) => {
  // Validate input
  if (!files?.length) throw new Error('No files selected');
  
  const validTools = ['compress', 'merge', 'convert', 'enhance', 'preview'];
  if (!validTools.includes(tool)) {
    throw new Error(`Invalid tool: ${tool}. Valid tools are: ${validTools.join(', ')}`);
  }

  // File count rules
  if (tool === 'merge' && files.length < 2) throw new Error('Merge needs 2+ files');
  if (['convert', 'enhance'].includes(tool) && files.length !== 1) {
    throw new Error(`${tool} requires exactly 1 file`);
  }

  const form = new FormData();
  
  // Use 'files' as field name to match server
  files.forEach(f => form.append('files', f));
  
  form.append('tool', tool);

  // Compression level
  if (tool === 'compress' && options.compressLevel) {
    const level = Math.max(1, Math.min(9, Math.round(options.compressLevel / 10)));
    form.append('compressLevel', level.toString());
  }

  // Merge order
  if (tool === 'merge' && options.order) {
    form.append('order', JSON.stringify(options.order));
  }

  // Convert format
  if (tool === 'convert' && options.format) {
    const ext = options.format.toLowerCase();
    if (!['jpg', 'jpeg', 'png', 'webp', 'mp3', 'wav', 'pdf'].includes(ext)) {
      throw new Error('Unsupported format');
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

    const token = getToken();
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);

    // Upload progress
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = Math.round((e.loaded / e.total) * 100);
        onProgress(percent);
      }
    };

    xhr.onload = () => {
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
          resolve({
            success: true,
            url: data.url.startsWith('http') ? data.url : API_BASE + data.url,
            fileName: data.fileName,
            size: data.size,
            originalSize: data.originalSize,
            savings: data.savings,
            tool: data.tool || tool
          });
        }
      } else {
        reject(new Error(data.message || `Server error: ${xhr.status}`));
      }
    };

    xhr.onerror = () => reject(new Error('Network error'));
    xhr.ontimeout = () => reject(new Error('Request timeout'));

    xhr.send(form);
  });
};

// === HISTORY ===
export const getHistory = (page = 1) =>
  fetch(`${API_BASE}/api/history?page=${page}`, { headers: authHeaders() })
    .then(handleResponse)
    .then(data => {
      if (data.success) {
        return { files: data.files, total: data.total, page: data.page, pages: data.pages };
      }
      throw new Error(data.message || 'Failed to fetch history');
    });

// === DOWNLOAD FILE ===
export const downloadFile = (filename) => {
  const token = getToken();
  const url = `${API_BASE}/api/download/${filename}`;
  
  if (token) {
    window.open(`${url}?token=${token}`, '_blank');
  } else {
    window.open(url, '_blank');
  }
};

// === HEALTH CHECK ===
export const checkHealth = () =>
  fetch(`${API_BASE}/api/health`)
    .then(handleResponse)
    .then(data => ({ ok: true, data }))
    .catch(() => ({ ok: false, error: 'Backend offline' }));

// === EXPORT ALL ===
export default {
  login,
  register,
  logout,
  isLoggedIn,
  fetchProfile,
  updateProfile,
  processFiles,
  getHistory,
  downloadFile,
  checkHealth
};