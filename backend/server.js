// server.js
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import multer from 'multer';
import compression from 'compression';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import sharp from 'sharp';
import { PDFDocument } from 'pdf-lib';
import archiver from 'archiver';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

// === Middleware ===
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://your-frontend-url.onrender.com',
    'https://online-file-editor4.onrender.com'
  ],
  credentials: true
}));
app.use(compression());
app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ extended: true, limit: '150mb' }));

// === Temporary Folders (Only for processing, not storage) ===
const uploadDir = path.join(__dirname, 'temp_uploads');
const processedDir = path.join(__dirname, 'temp_processed');
[uploadDir, processedDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Serve temporary files (they will be deleted after processing)
app.use('/temp_uploads', express.static(uploadDir));
app.use('/temp_processed', express.static(processedDir));

// === MongoDB Atlas Connection ===
const connectDB = async () => {
  try {
    console.log('🔗 Connecting to MongoDB Atlas...');
    
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is not defined in environment variables');
    }

    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 15000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
      w: 'majority'
    });
    
    console.log('✅ MongoDB Atlas Connected Successfully');
    console.log(`📊 Database: ${conn.connection.name}`);
    console.log(`🌐 Host: ${conn.connection.host}`);
    
    // Test the connection
    await mongoose.connection.db.admin().ping();
    console.log('✅ Database ping successful');
    
  } catch (e) {
    console.error('❌ MongoDB connection error:', e.message);
    
    if (e.name === 'MongoServerSelectionError') {
      console.error('💡 Check: Internet connection, Atlas IP whitelist, and credentials');
    }
    
    console.log('🔄 Retrying connection in 5 seconds...');
    setTimeout(connectDB, 5000);
  }
};

// Handle connection events
mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB disconnected');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

connectDB();

// === Enhanced Schemas for Atlas Storage ===
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true, 
    minlength: 3, 
    maxlength: 30,
    index: true
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true,
    index: true
  },
  password: { 
    type: String, 
    required: true, 
    minlength: 6 
  },
  profile: { 
    fullName: { type: String, default: '' },
    company: { type: String, default: '' },
    phone: { type: String, default: '' },
    location: { type: String, default: '' },
    avatar: { type: String, default: '' }
  },
  preferences: { 
    theme: { type: String, default: 'light', enum: ['light', 'dark'] }, 
    notifications: { type: Boolean, default: true } 
  },
  stats: {
    totalFiles: { type: Number, default: 0, min: 0 },
    totalSize: { type: Number, default: 0, min: 0 },
    totalCompressed: { type: Number, default: 0, min: 0 },
    spaceSaved: { type: Number, default: 0, min: 0 },
    totalDownloads: { type: Number, default: 0, min: 0 }
  },
  lastActive: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true, index: true },
  originalName: { type: String, required: true },
  size: { type: Number, required: true, min: 0 },
  compressedSize: { type: Number, required: true, min: 0 },
  type: { type: String, required: true },
  mimeType: { type: String, required: true },
  owner: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  downloadCount: { type: Number, default: 0, min: 0 },
  compressionRatio: { type: Number, min: 0, max: 100 },
  toolUsed: { 
    type: String, 
    required: true,
    enum: ['compress', 'merge', 'convert', 'enhance', 'preview'] 
  },
  // Store file content in MongoDB GridFS or as Buffer for small files
  fileData: { type: Buffer }, // For small files (<16MB)
  // For larger files, we'll use GridFS
  gridFsId: { type: mongoose.Schema.Types.ObjectId }, // Reference to GridFS file
  metadata: {
    originalPath: String,
    processedPath: String,
    processingTime: Number,
    quality: Number
  }
}, { 
  timestamps: true 
});

// Create indexes for better performance
fileSchema.index({ owner: 1, createdAt: -1 });
fileSchema.index({ toolUsed: 1 });
fileSchema.index({ createdAt: 1 });

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);

// === GridFS Setup for Large File Storage in Atlas ===
let gfs;
const conn = mongoose.connection;
conn.once('open', () => {
  console.log('📁 GridFS initialized for large file storage');
});

// === Multer Configuration (Temporary only) ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-]/g, '_');
    const tempName = `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}_${safeName}`;
    cb(null, tempName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB max
  fileFilter: (req, file, cb) => {
    // Allow all file types for processing
    cb(null, true);
  }
});

// === Auth Middleware ===
const auth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader) {
      return res.status(401).json({ 
        success: false, 
        message: 'No authorization header provided' 
      });
    }

    const token = authHeader.replace('Bearer', '').trim();
    
    if (!token || token === 'null' || token === 'undefined') {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication token is required' 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Update last active timestamp
    await User.findByIdAndUpdate(user._id, { lastActive: new Date() });
    
    req.user = user;
    next();
    
  } catch (error) {
    console.error('Auth error:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired' });
    }
    
    res.status(500).json({ success: false, message: 'Authentication failed' });
  }
};

// === Helper Functions ===
const updateUserStats = async (userId, originalSize, compressedSize) => {
  try {
    await User.findByIdAndUpdate(userId, {
      $inc: {
        'stats.totalFiles': 1,
        'stats.totalSize': originalSize,
        'stats.totalCompressed': compressedSize,
        'stats.spaceSaved': originalSize - compressedSize
      },
      lastActive: new Date()
    });
  } catch (error) {
    console.error('Error updating user stats:', error.message);
  }
};

const cleanupTempFiles = (files) => {
  if (files && Array.isArray(files)) {
    files.forEach(file => {
      try {
        if (fs.existsSync(file.path)) {
          fs.unlinkSync(file.path);
          console.log(`🧹 Cleaned up temp file: ${file.path}`);
        }
      } catch (cleanupError) {
        console.warn('Cleanup warning:', cleanupError.message);
      }
    });
  }
};

const storeFileInDatabase = async (filePath, filename, metadata = {}) => {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    
    // For files smaller than 16MB, store directly in document
    if (fileBuffer.length < 16 * 1024 * 1024) {
      return {
        fileData: fileBuffer,
        gridFsId: null
      };
    } else {
      // For larger files, you would implement GridFS here
      console.log('Large file detected, consider implementing GridFS');
      return {
        fileData: null,
        gridFsId: null
      };
    }
  } catch (error) {
    console.error('Error storing file in database:', error.message);
    return { fileData: null, gridFsId: null };
  }
};

// === Routes ===

// Health check with detailed DB info
app.get('/api/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    const statusText = dbStatus === 1 ? 'Connected' : 'Disconnected';
    
    const dbInfo = {
      status: statusText,
      name: mongoose.connection.db?.databaseName || 'Unknown',
      host: mongoose.connection.host || 'Unknown',
      readyState: dbStatus
    };

    // Get some stats from database
    const userCount = await User.countDocuments();
    const fileCount = await File.countDocuments();
    const totalSize = await File.aggregate([
      { $group: { _id: null, total: { $sum: '$size' } } }
    ]);

    res.json({ 
      success: true, 
      message: 'FileMaster Pro API Server',
      database: dbInfo,
      statistics: {
        users: userCount,
        files: fileCount,
        totalStorage: totalSize[0]?.total || 0
      },
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Health check failed',
      error: error.message 
    });
  }
});

// Database diagnostics
app.get('/api/diagnostics', auth, async (req, res) => {
  try {
    const collections = await mongoose.connection.db.listCollections().toArray();
    const userStats = await User.aggregate([
      { $group: { 
        _id: null, 
        totalUsers: { $sum: 1 },
        activeUsers: { 
          $sum: { 
            $cond: [{ $gte: ['$lastActive', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)] }, 1, 0] 
          } 
        }
      }}
    ]);

    const fileStats = await File.aggregate([
      { $group: { 
        _id: null, 
        totalFiles: { $sum: 1 },
        totalSize: { $sum: '$size' },
        totalDownloads: { $sum: '$downloadCount' },
        avgCompression: { $avg: '$compressionRatio' }
      }}
    ]);

    res.json({
      success: true,
      database: {
        name: mongoose.connection.db.databaseName,
        collections: collections.map(c => c.name),
        userStats: userStats[0] || {},
        fileStats: fileStats[0] || {}
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Diagnostics failed',
      error: error.message
    });
  }
});

// === AUTHENTICATION ROUTES ===

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, fullName = '', company = '' } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username, email, and password are required' 
      });
    }

    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: existingUser.email === email.toLowerCase() 
          ? 'Email already registered' 
          : 'Username already taken' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ 
      username: username.trim(), 
      email: email.toLowerCase().trim(), 
      password: hashedPassword, 
      profile: { fullName: fullName.trim(), company: company.trim() } 
    });
    
    await user.save();

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profile: user.profile,
        stats: user.stats,
        preferences: user.preferences
      }
    });

  } catch (error) {
    console.error('Register error:', error);
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ 
        success: false, 
        message: messages[0] || 'Validation failed' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Server error during registration' 
    });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    const user = await User.findOne({ 
      email: email.toLowerCase().trim() 
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    // Update last active
    await User.findByIdAndUpdate(user._id, { lastActive: new Date() });

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profile: user.profile,
        stats: user.stats,
        preferences: user.preferences
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});

// PROFILE
app.get('/api/profile', auth, async (req, res) => {
  try {
    const files = await File.find({ owner: req.user._id });
    const stats = {
      totalFiles: files.length,
      totalSize: files.reduce((sum, file) => sum + file.size, 0),
      totalCompressed: files.reduce((sum, file) => sum + file.compressedSize, 0),
      spaceSaved: files.reduce((sum, file) => sum + (file.size - file.compressedSize), 0),
      totalDownloads: files.reduce((sum, file) => sum + file.downloadCount, 0)
    };

    res.json({
      success: true,
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        profile: req.user.profile,
        preferences: req.user.preferences,
        stats: stats,
        lastActive: req.user.lastActive
      }
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch profile' 
    });
  }
});

// UPDATE PROFILE
app.put('/api/profile', auth, async (req, res) => {
  try {
    const updates = req.body;
    const allowedFields = ['fullName', 'company', 'phone', 'location', 'theme', 'notifications'];
    const updateData = {};

    allowedFields.forEach(field => {
      if (updates[field] !== undefined) {
        if (['theme', 'notifications'].includes(field)) {
          updateData[`preferences.${field}`] = updates[field];
        } else {
          updateData[`profile.${field}`] = updates[field];
        }
      }
    });

    const user = await User.findByIdAndUpdate(
      req.user._id, 
      updateData, 
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profile: user.profile,
        preferences: user.preferences,
        stats: user.stats
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Profile update failed' 
    });
  }
});

// === FILE PROCESSING ROUTES ===

// PROCESS FILES
app.post('/api/process', auth, upload.array('files'), async (req, res) => {
  let uploadedFiles = [];
  
  try {
    const files = req.files;
    if (!files || files.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No files uploaded' 
      });
    }

    const { tool, compressLevel, format, order } = req.body;
    
    const validTools = ['compress', 'merge', 'convert', 'enhance', 'preview'];
    if (!validTools.includes(tool)) {
      return res.status(400).json({ 
        success: false, 
        message: `Invalid tool. Use: ${validTools.join(', ')}` 
      });
    }

    // Store uploaded files for cleanup
    uploadedFiles = files;

    // Tool-specific validations
    if (tool === 'merge' && files.length < 2) {
      return res.status(400).json({ 
        success: false, 
        message: 'Merge requires at least 2 files' 
      });
    }

    if (['convert', 'enhance'].includes(tool) && files.length !== 1) {
      return res.status(400).json({ 
        success: false, 
        message: `${tool} requires exactly 1 file` 
      });
    }

    let outputPath, mimeType, compressedSize;
    const originalSize = files.reduce((sum, file) => sum + file.size, 0);
    let fileName = '';

    // Process based on tool
    if (tool === 'compress') {
      const level = Math.max(1, Math.min(9, parseInt(compressLevel) || 6));
      outputPath = path.join(processedDir, `compressed_${Date.now()}.zip`);
      const output = fs.createWriteStream(outputPath);
      const archive = archiver('zip', { zlib: { level } });
      
      await new Promise((resolve, reject) => {
        archive.pipe(output);
        files.forEach(file => archive.file(file.path, { name: file.originalname }));
        archive.on('error', reject);
        output.on('close', resolve);
        archive.finalize();
      });

      compressedSize = fs.statSync(outputPath).size;
      fileName = files.length === 1 
        ? `${path.parse(files[0].originalname).name}_compressed.zip` 
        : `batch_compressed_${Date.now()}.zip`;
      mimeType = 'application/zip';

    } else if (tool === 'merge') {
      const nonPdfFiles = files.filter(file => file.mimetype !== 'application/pdf');
      if (nonPdfFiles.length > 0) {
        return res.status(400).json({ 
          success: false, 
          message: 'All files must be PDFs for merging' 
        });
      }

      const pdfDoc = await PDFDocument.create();
      const orderArray = order ? JSON.parse(order) : files.map(file => file.originalname);
      
      for (const name of orderArray) {
        const file = files.find(f => f.originalname === name);
        if (!file) continue;
        
        const sourceBytes = fs.readFileSync(file.path);
        const sourceDoc = await PDFDocument.load(sourceBytes);
        const pages = await pdfDoc.copyPages(sourceDoc, sourceDoc.getPageIndices());
        pages.forEach(page => pdfDoc.addPage(page));
      }

      const pdfBytes = await pdfDoc.save();
      outputPath = path.join(processedDir, `merged_${Date.now()}.pdf`);
      fs.writeFileSync(outputPath, pdfBytes);
      compressedSize = pdfBytes.length;
      fileName = 'merged_document.pdf';
      mimeType = 'application/pdf';

    } else if (tool === 'convert') {
      const file = files[0];
      const extension = format.toLowerCase();
      
      const validImageFormats = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
      const validAudioFormats = ['mp3', 'wav', 'ogg'];
      
      if (![...validImageFormats, ...validAudioFormats].includes(extension)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Unsupported format' 
        });
      }

      outputPath = path.join(processedDir, `converted_${Date.now()}.${extension}`);
      
      if (validImageFormats.includes(extension)) {
        await sharp(file.path)
          .toFormat(extension === 'jpg' ? 'jpeg' : extension)
          .toFile(outputPath);
        mimeType = `image/${extension === 'jpg' ? 'jpeg' : extension}`;
      } else {
        fs.copyFileSync(file.path, outputPath);
        mimeType = `audio/${extension}`;
      }
      
      compressedSize = fs.statSync(outputPath).size;
      fileName = `${path.parse(file.originalname).name}.${extension}`;

    } else if (tool === 'enhance') {
      const file = files[0];
      
      if (!file.mimetype.startsWith('image/')) {
        return res.status(400).json({ 
          success: false, 
          message: 'Only images can be enhanced' 
        });
      }

      outputPath = path.join(processedDir, `enhanced_${Date.now()}.webp`);
      await sharp(file.path)
        .rotate()
        .sharpen()
        .modulate({ brightness: 1.1, saturation: 1.2 })
        .webp({ quality: 85 })
        .toFile(outputPath);
      
      compressedSize = fs.statSync(outputPath).size;
      fileName = `${path.parse(file.originalname).name}_enhanced.webp`;
      mimeType = 'image/webp';
    }

    // Store file record in MongoDB Atlas
    const fileRecord = new File({
      filename: path.basename(outputPath),
      originalName: fileName,
      size: originalSize,
      compressedSize: compressedSize,
      type: tool,
      mimeType: mimeType,
      owner: req.user._id,
      compressionRatio: originalSize > 0 ? 
        Number(((originalSize - compressedSize) / originalSize * 100).toFixed(2)) : 0,
      toolUsed: tool,
      metadata: {
        originalPath: files.map(f => f.path).join(','),
        processedPath: outputPath,
        processingTime: Date.now(),
        quality: compressLevel || 85
      }
    });

    await fileRecord.save();
    await updateUserStats(req.user._id, originalSize, compressedSize);

    res.json({
      success: true,
      message: `File ${tool}ed successfully`,
      data: {
        url: `/temp_processed/${path.basename(outputPath)}`,
        downloadUrl: `/api/download/${path.basename(outputPath)}`,
        fileName: fileName,
        size: compressedSize,
        originalSize: originalSize,
        savings: originalSize - compressedSize,
        compressionRatio: fileRecord.compressionRatio,
        tool: tool,
        fileId: fileRecord._id
      }
    });

  } catch (error) {
    console.error('Process error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'File processing failed' 
    });
  } finally {
    // Cleanup uploaded temporary files
    cleanupTempFiles(uploadedFiles);
  }
});

// FILE HISTORY
app.get('/api/history', auth, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;
    
    const files = await File.find({ owner: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-fileData -gridFsId'); // Exclude large binary data
      
    const total = await File.countDocuments({ owner: req.user._id });
    
    res.json({ 
      success: true, 
      message: 'File history retrieved',
      data: {
        files, 
        pagination: {
          total,
          page,
          pages: Math.ceil(total / limit),
          limit
        }
      }
    });
  } catch (error) {
    console.error('History error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch file history' 
    });
  }
});

// DOWNLOAD FILE
app.get('/api/download/:filename', auth, async (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(processedDir, filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ 
        success: false, 
        message: 'File not found' 
      });
    }

    // Update download counts
    await File.findOneAndUpdate(
      { filename },
      { $inc: { downloadCount: 1 } }
    );

    await User.findByIdAndUpdate(req.user._id, {
      $inc: { 'stats.totalDownloads': 1 }
    });

    res.download(filePath, (err) => {
      if (err) {
        console.error('Download error:', err);
        res.status(500).json({ 
          success: false, 
          message: 'Download failed' 
        });
      }
      
      // Optionally cleanup processed file after download
      setTimeout(() => {
        try {
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            console.log(`🧹 Cleaned up downloaded file: ${filePath}`);
          }
        } catch (cleanupError) {
          console.warn('Download cleanup warning:', cleanupError.message);
        }
      }, 30000); // Cleanup after 30 seconds
    });

  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Download failed' 
    });
  }
});

// DELETE FILE
app.delete('/api/files/:fileId', auth, async (req, res) => {
  try {
    const fileId = req.params.fileId;
    const file = await File.findOne({ _id: fileId, owner: req.user._id });
    
    if (!file) {
      return res.status(404).json({ 
        success: false, 
        message: 'File not found' 
      });
    }

    // Clean up local file if it exists
    const filePath = path.join(processedDir, file.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await File.findByIdAndDelete(fileId);

    res.json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete file' 
    });
  }
});

// === ADMIN ROUTES (Optional) ===
app.get('/api/admin/stats', auth, async (req, res) => {
  try {
    // Simple admin check (you might want to implement proper admin roles)
    if (req.user.email !== 'admin@example.com') {
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied' 
      });
    }

    const stats = await User.aggregate([
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          totalFiles: { $sum: '$stats.totalFiles' },
          totalStorage: { $sum: '$stats.totalSize' },
          totalSpaceSaved: { $sum: '$stats.spaceSaved' },
          avgCompression: { $avg: '$stats.spaceSaved' }
        }
      }
    ]);

    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select('username email createdAt lastActive');

    res.json({
      success: true,
      data: {
        overview: stats[0] || {},
        recentUsers,
        database: {
          name: mongoose.connection.db.databaseName,
          collections: await mongoose.connection.db.listCollections().toArray()
        }
      }
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch admin stats' 
    });
  }
});

// === ERROR HANDLING ===
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
});

app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found'
  });
});

// === START SERVER ===
const PORT = process.env.PORT || 5001;
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 FileMaster Pro Backend STARTED');
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`❤️  Health: http://localhost:${PORT}/api/health`);
  console.log(`📊 Database: ${process.env.MONGODB_URI ? 'Atlas' : 'Local'}`);
  console.log(`⚡ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('====================================');
});