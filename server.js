require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');

const app = express();

// 🛡️ Proxy support for Render/Heroku (Fixes Rate Limit & HTTPS detection)
app.set('trust proxy', 1);

// Middlewares
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json());
app.use(cors());

// Uploads फोल्डर अगर मौजूद नहीं है तो ऑटोमैटिक बना दें
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// DDoS Attack Protection Limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: '🛑 Security Warning: Too many requests. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: '🛑 Security Warning: Too many attempts. Please return after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);
app.use('/uploads', express.static(UPLOADS_DIR));

// 🛡️ MongoDB Connection Setup
const dbURI = process.env.MONGO_URI;

if (!dbURI) {
  console.log("⚠️ Warning: MONGO_URI not found in .env file!");
} else {
  mongoose.connect(dbURI)
    .then(() => console.log('🚀 Successfully connected to MongoDB cloud!'))
    .catch(err => console.log('🛑 MongoDB connection failed:', err.message));
}

// Check Dynamic Database Connection
const checkDatabaseConnection = (req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ 
      message: '🛑 Database server is currently undergoing maintenance. Please try again later.' 
    });
  }
  next();
};

// ==================== Auth Middlewares ====================
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: '🛑 Access Denied! No Token Provided.' });

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key', (err, decoded) => {
    if (err) return res.status(403).json({ message: '🛑 Invalid or Expired Token!' });
    req.user = decoded;
    next();
  });
};

const verifyAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: '🛑 Access Denied! Admin Privileges Required.' });
  }
};

// ==================== Mongoose Models ====================
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  mobile: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  course: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

const LogSchema = new mongoose.Schema({
  userName: String,
  mobile: String,
  loginTime: { type: Date, default: Date.now },
  logoutTime: Date,
  durationInSeconds: Number
});
const Log = mongoose.model('Log', LogSchema);

const MaterialSchema = new mongoose.Schema({
  title: { type: String, required: true },
  course: { type: String, required: true },
  semester: { type: String, required: true },
  fileUrl: { type: String, required: true },
  fileType: { type: String, required: true }, 
  uploadedAt: { type: Date, default: Date.now }
});
const Material = mongoose.model('Material', MaterialSchema);

// In-Memory OTP Store with Expiry Management
const otpStore = new Map();

// Helper: Delete OTP after 10 minutes
const setOtpWithExpiry = (mobile, otp) => {
  otpStore.set(mobile, otp);
  setTimeout(() => otpStore.delete(mobile), 10 * 60 * 1000);
};

// ==================== Multer Storage Setup ====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    // Filename sanitization (removes spaces & dangerous chars)
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${Date.now()}-${sanitizedName}`);
  }
});

const allowedFileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedExtensions = ['.pdf', '.jpg', '.jpeg', '.png'];
  const allowedMimeTypes = ['application/pdf', 'image/jpeg', 'image/png'];

  if (!allowedExtensions.includes(ext) || !allowedMimeTypes.includes(file.mimetype)) {
    return cb(new Error('🛑 Security Warning: Only .pdf files and genuine images (.jpg, .png) are allowed!'), false);
  }
  cb(null, true);
};

const upload = multer({ 
  storage: storage,
  fileFilter: allowedFileFilter,
  limits: { fileSize: 15 * 1024 * 1024 }
});

const isPasswordStrong = (password) => {
  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return strongPasswordRegex.test(password);
};

// ==================== REST APIs ====================

// 📤 Protected Study Material Upload (Admin Only)
app.post('/api/upload-material', checkDatabaseConnection, verifyToken, verifyAdmin, (req, res) => {
  upload.single('pdfFile')(req, res, async (err) => {
    if (err) return res.status(400).json({ message: err.message });
    try {
      const { title, course, semester } = req.body;
      if (!req.file) return res.status(400).json({ message: 'Please select a valid file!' });
      
      const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
      const ext = path.extname(req.file.filename).toLowerCase();
      const fileType = ext === '.pdf' ? 'pdf' : 'image';

      const newMaterial = new Material({ title, course: course.toLowerCase(), semester, fileUrl, fileType });
      await newMaterial.save();
      res.status(201).json({ message: '🚀 Study material uploaded successfully!' });
    } catch (error) { 
      res.status(500).json({ message: 'Server glitch during upload' }); 
    }
  });
});

// 🔒 Admin Get All Materials
app.get('/api/admin/materials', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const materials = await Material.find().sort({ uploadedAt: -1 });
    res.json(materials);
  } catch (error) { 
    res.status(500).json({ message: 'Error fetching materials' }); 
  }
});

// 🗑️ Admin Delete Material (Clean Async Unlink)
app.delete('/api/admin/delete-material/:id', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const materialId = req.params.id;
    const material = await Material.findById(materialId);
    if (!material) return res.status(404).json({ message: 'File record not found!' });

    const filename = path.basename(material.fileUrl);
    const filePath = path.join(UPLOADS_DIR, filename);

    // Modern Promises-based File Unlink
    try {
      if (fs.existsSync(filePath)) {
        await fs.promises.unlink(filePath);
      }
    } catch (fileErr) {
      console.error('File removal error from disk:', fileErr.message);
    }

    await Material.findByIdAndDelete(materialId);
    res.status(200).json({ message: '🗑️ Deleted from server disk and database!' });
  } catch (error) { 
    res.status(500).json({ message: 'Server error during deletion' }); 
  }
});

// 📚 Student Get Materials
app.get('/api/materials/:course/:semester', checkDatabaseConnection, async (req, res) => {
  try {
    const { course, semester } = req.params;
    const materials = await Material.find({ course: course.toLowerCase(), semester });
    res.json(materials);
  } catch (error) { 
    res.status(500).json({ message: 'Data fetch error' }); 
  }
});

// 🔒 Admin Get Student Logs
app.get('/api/admin/logs', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const logs = await Log.find().sort({ loginTime: -1 });
    res.json(logs);
  } catch (error) { 
    res.status(500).json({ message: 'Logs fetch error' }); 
  }
});

// 🔒 Admin Logout All Users
app.post('/api/admin/logout-all', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const currentTime = new Date();
    await Log.updateMany(
      { logoutTime: { $exists: false } }, 
      { $set: { logoutTime: currentTime, durationInSeconds: 0 } }
    );
    res.status(200).json({ message: '🚀 All students logged out successfully!' });
  } catch (error) { 
    res.status(500).json({ message: 'Server error during logout-all' }); 
  }
});

// 📝 Student Registration
app.post('/api/register', checkDatabaseConnection, async (req, res) => {
  try {
    const { name, mobile, password, course } = req.body;
    if (typeof mobile !== 'string' || typeof password !== 'string' || typeof course !== 'string') {
      return res.status(400).json({ message: '🛑 Invalid input format!' });
    }
    if (!isPasswordStrong(password)) {
      return res.status(400).json({ message: '🛑 Password must contain 8+ chars, 1 uppercase, 1 lowercase, 1 number, & 1 special char.' });
    }

    const userExists = await User.findOne({ mobile });
    if (userExists) return res.status(400).json({ message: 'This mobile number is already registered!' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, mobile, password: hashedPassword, course: course.toLowerCase() });
    await newUser.save();

    res.status(201).json({ message: 'Registration successful!' });
  } catch (error) { 
    res.status(500).json({ message: 'Server error during registration' }); 
  }
});

// 🔑 Student & Admin Login
app.post('/api/login', authLimiter, checkDatabaseConnection, async (req, res) => {
  try {
    let { mobile, password, role } = req.body;
    if (typeof mobile !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: '🛑 Invalid input format!' });
    }

    const SUPER_ADMIN_MOBILE = process.env.SUPER_ADMIN_MOBILE; 
    if (role === 'admin' && mobile !== SUPER_ADMIN_MOBILE) {
      return res.status(403).json({ message: '🛑 Access denied! Not authorized as Admin.' });
    }

    const user = await User.findOne({ mobile });
    if (!user) return res.status(400).json({ message: 'Incorrect mobile number or password!' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Incorrect mobile number or password!' });

    const jwtSecret = process.env.JWT_SECRET || 'fallback_secret_key';
    const token = jwt.sign(
      { userId: user._id, role: role || 'student', mobile: user.mobile, course: user.course }, 
      jwtSecret, 
      { expiresIn: '12h' }
    );

    const newLog = new Log({ userName: user.name, mobile: user.mobile, loginTime: new Date() });
    const savedLog = await newLog.save();

    res.status(200).json({ 
      message: 'Login successful!', 
      name: user.name, 
      mobile: user.mobile, 
      role: role || 'student', 
      course: user.course || 'bca', 
      token: token, 
      logId: savedLog._id 
    });
  } catch (error) { 
    res.status(500).json({ message: 'Server error during login' }); 
  }
});

// 🚪 User Logout
app.post('/api/logout', checkDatabaseConnection, async (req, res) => {
  try {
    const { logId } = req.body;
    if (!logId) return res.status(400).json({ message: 'Log ID is required' });

    const log = await Log.findById(logId);
    if (log) { 
      log.logoutTime = new Date(); 
      const diffInMillieSeconds = Math.abs(log.logoutTime.getTime() - log.loginTime.getTime()); 
      log.durationInSeconds = Math.round(diffInMillieSeconds / 1000); 
      await log.save(); 
      res.status(200).json({ message: 'Logout data saved successfully!' }); 
    } else { 
      res.status(404).json({ message: 'Log record not found' }); 
    }
  } catch (error) { 
    res.status(500).json({ message: 'Server error during logout' }); 
  }
});

// 🔑 Send OTP for Forgot Password
app.post('/api/send-otp', authLimiter, checkDatabaseConnection, async (req, res) => {
  try {
    const { mobile } = req.body;
    const user = await User.findOne({ mobile });
    if (!user) return res.status(404).json({ message: 'This mobile number is not registered!' });

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    setOtpWithExpiry(mobile, otp);
    
    console.log(`\n====================================\n🔑 FORGOT PASSWORD OTP for ${mobile}: ${otp}\n====================================\n`);
    res.status(200).json({ message: 'OTP sent successfully!' });
  } catch (error) { 
    res.status(500).json({ message: 'Error sending OTP' }); 
  }
});

// 🔄 Verify OTP & Reset Password
app.post('/api/verify-otp-reset', checkDatabaseConnection, async (req, res) => {
  try {
    const { mobile, otp, newPassword } = req.body;

    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({ message: '🛑 Password must meet security requirements!' });
    }
    
    const storedOtp = otpStore.get(mobile);
    if (!storedOtp || storedOtp !== otp) {
      return res.status(400).json({ message: 'Incorrect or expired OTP!' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ mobile }, { password: hashedPassword });
    otpStore.delete(mobile);

    res.status(200).json({ message: 'Password reset successfully!' });
  } catch (error) { 
    res.status(500).json({ message: 'Error resetting password' }); 
  }
});

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.stack);
  res.status(500).json({ message: 'Internal Server Error' });
});

// Server Listening Port
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend server successfully running on port ${PORT}!`);
});