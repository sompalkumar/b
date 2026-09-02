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
const crypto = require('crypto');
const mongoSanitize = require('express-mongo-sanitize');

// ==================== Critical Environment Validation ====================
if (!process.env.JWT_SECRET) {
  console.error('🛑 FATAL: JWT_SECRET is not defined. Server cannot start securely.');
  process.exit(1);
}
if (!process.env.MONGO_URI) {
  console.error('🛑 FATAL: MONGO_URI is not defined. Server cannot start.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

// Proxy support for Render/Heroku
app.set('trust proxy', 1);

// ==================== Core Middlewares ====================
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json());

// NoSQL Injection Prevention — sanitizes req.body, req.params, req.query
app.use(mongoSanitize());

// Restricted CORS — only allow known frontend origins
const ALLOWED_ORIGINS = [
  'https://bca-35ms.onrender.com',       // Backend itself (if self-referencing)
  'https://bcaeasylearn.vercel.app',    // Exact Production Frontend Domain
  'https://bca-easy-lms.vercel.app',    // Additional Vercel domain
  'https://bca-easy-lms.netlify.app',   // Netlify frontend (if applicable)
  'http://localhost:5173',              // Local Vite dev server
  'http://localhost:4173',              // Local Vite preview
  'http://localhost:3000'               // Alternative local dev
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy: origin ${origin} is not allowed.`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Pre-flight OPTIONS Requests (Fixed path matching for modern Express / path-to-regexp)
app.options(/(.*)/, cors());

// Uploads Directory Setup
const UPLOADS_DIR = path.resolve(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Serve Static Files BEFORE Rate Limiter
app.use('/uploads', express.static(UPLOADS_DIR));

// DDoS Protection Limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  message: { message: '🛑 Too many requests. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { message: '🛑 Too many attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('🚀 Successfully connected to MongoDB!'))
  .catch(err => {
    console.error('🛑 MongoDB connection failed:', err.message);
    process.exit(1);
  });

// Check Database Connection Middleware
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

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: '🛑 Invalid or Expired Token!' });
    req.user = decoded;
    next();
  });
};

const verifyAdmin = (req, res, next) => {
  if (req.user && String(req.user.role).toLowerCase() === 'admin') {
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
  course: { type: String, required: true },
  role: { type: String, default: 'student', enum: ['student', 'admin'] }
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

// Fixed: Added category, question, options, correctOption for full Quiz support
const MaterialSchema = new mongoose.Schema({
  title: { type: String, required: true },
  course: { type: String, required: true },
  semester: { type: String, required: true },
  fileUrl: { type: String, default: '' },
  driveUrl: { type: String, default: '' },
  fileType: { type: String, default: 'pdf' },
  category: { type: String, default: 'notes', enum: ['notes', 'pyq', 'quiz'] },
  question: { type: String, default: '' },
  options: { type: [String], default: [] },
  correctOption: { type: String, default: '' },
  uploadedAt: { type: Date, default: Date.now }
});
const Material = mongoose.model('Material', MaterialSchema);

// ==================== In-Memory OTP Store (with timer tracking) ====================
const otpStore = new Map();
const setOtpWithExpiry = (mobile, otp) => {
  if (otpStore.has(mobile)) {
    clearTimeout(otpStore.get(mobile).timer);
  }
  const timer = setTimeout(() => otpStore.delete(mobile), 10 * 60 * 1000); // 10 min
  otpStore.set(mobile, { otp, timer });
};
const getStoredOtp = (mobile) => {
  const entry = otpStore.get(mobile);
  return entry ? entry.otp : null;
};

// Multer Storage Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
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

// 🔑 FIXED COMBINED LOGIN ENDPOINT
app.post('/api/login', authLimiter, checkDatabaseConnection, async (req, res) => {
  try {
    let { mobile, password } = req.body;
    if (typeof mobile !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: '🛑 Invalid input format!' });
    }

    const user = await User.findOne({ mobile });
    if (!user) return res.status(400).json({ message: 'Incorrect mobile number or password!' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Incorrect mobile number or password!' });

    const SUPER_ADMIN_MOBILE = process.env.SUPER_ADMIN_MOBILE;
    const isSuperAdmin = SUPER_ADMIN_MOBILE && mobile === SUPER_ADMIN_MOBILE;
    const userRoleClean = String(user.role || '').toLowerCase().trim();
    const isAdminRole = userRoleClean === 'admin' || isSuperAdmin;

    if (isAdminRole) {
      const token = jwt.sign(
        { userId: user._id, role: 'admin', mobile: user.mobile, course: user.course },
        JWT_SECRET,
        { expiresIn: '12h' }
      );
      return res.status(200).json({
        message: 'Admin login successful!',
        name: user.name,
        mobile: user.mobile,
        role: 'admin',
        token
      });
    }

    // Student Token & Log
    const token = jwt.sign(
      { userId: user._id, role: 'student', mobile: user.mobile, course: user.course },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    const newLog = new Log({ userName: user.name, mobile: user.mobile, loginTime: new Date() });
    const savedLog = await newLog.save();

    res.status(200).json({
      message: 'Login successful!',
      name: user.name,
      mobile: user.mobile,
      role: 'student',
      course: user.course || 'bca',
      token,
      logId: savedLog._id
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// 👑 Strict Admin-Only Login
app.post('/api/admin-login', authLimiter, checkDatabaseConnection, async (req, res) => {
  try {
    const { mobile, password } = req.body;
    if (typeof mobile !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: '🛑 Invalid input format!' });
    }

    const user = await User.findOne({ mobile });
    if (!user) return res.status(400).json({ message: 'Incorrect mobile number or password!' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Incorrect mobile number or password!' });

    const SUPER_ADMIN_MOBILE = process.env.SUPER_ADMIN_MOBILE;
    const isSuperAdmin = SUPER_ADMIN_MOBILE && mobile === SUPER_ADMIN_MOBILE;
    const userRoleClean = String(user.role || '').toLowerCase().trim();
    const isAdminRole = userRoleClean === 'admin';

    if (!isSuperAdmin && !isAdminRole) {
      return res.status(403).json({ message: '🛑 Access Denied! You are not an admin.' });
    }

    const token = jwt.sign(
      { userId: user._id, role: 'admin', mobile: user.mobile, course: user.course },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.status(200).json({
      message: 'Admin login successful!',
      name: user.name,
      mobile: user.mobile,
      role: 'admin',
      token
    });
  } catch (error) { 
    res.status(500).json({ message: 'Server error during admin login' }); 
  }
});

// 📤 Upload Material (Admin Only)
app.post('/api/upload-material', checkDatabaseConnection, verifyToken, verifyAdmin, (req, res) => {
  upload.single('pdfFile')(req, res, async (err) => {
    if (err) return res.status(400).json({ message: err.message });
    try {
      const { title, course, semester, driveUrl, category, question, options, correctOption } = req.body;

      if (!title || typeof title !== 'string' || !title.trim()) {
        return res.status(400).json({ message: 'Title / Topic Name is required!' });
      }

      const materialCategory = category || 'notes';

      // Quiz handling
      if (materialCategory === 'quiz') {
        if (!question || typeof question !== 'string' || !question.trim()) {
          return res.status(400).json({ message: 'Quiz question is required!' });
        }
        let parsedOptions = [];
        try {
          parsedOptions = typeof options === 'string' ? JSON.parse(options) : options;
        } catch {
          return res.status(400).json({ message: 'Invalid options format!' });
        }
        if (!Array.isArray(parsedOptions) || parsedOptions.length < 2) {
          return res.status(400).json({ message: 'At least 2 quiz options are required!' });
        }

        const newQuiz = new Material({
          title: title.trim(),
          course: (course || 'bca').toLowerCase(),
          semester: semester || '1',
          category: 'quiz',
          question: question.trim(),
          options: parsedOptions,
          correctOption: correctOption || 'A'
        });

        await newQuiz.save();
        return res.status(201).json({ message: '🚀 Quiz uploaded successfully!' });
      }

      // Notes / PYQ handling
      if (!req.file && (!driveUrl || driveUrl.trim() === '')) {
        return res.status(400).json({ message: 'Please upload a file OR provide a Google Drive link!' });
      }

      let fileUrl = '';
      let fileType = 'pdf';

      if (req.file) {
        fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
        const ext = path.extname(req.file.filename).toLowerCase();
        fileType = ext === '.pdf' ? 'pdf' : 'image';
      } else if (driveUrl) {
        let formattedDriveUrl = driveUrl.trim();
        if (formattedDriveUrl.includes('drive.google.com') && formattedDriveUrl.includes('/view')) {
          formattedDriveUrl = formattedDriveUrl.replace(/\/view.*$/, '/preview');
        }
        fileUrl = formattedDriveUrl;
        fileType = 'pdf';
      }

      const newMaterial = new Material({ 
        title: title.trim(), 
        course: (course || 'bca').toLowerCase(), 
        semester: semester || '1', 
        fileUrl, 
        driveUrl: driveUrl || fileUrl, 
        fileType,
        category: materialCategory
      });

      await newMaterial.save();
      res.status(201).json({ message: '🚀 Study material uploaded successfully!' });
    } catch (error) { 
      console.error('Upload error:', error.message);
      res.status(500).json({ message: 'Server glitch during upload' }); 
    }
  });
});

// Admin Get All Materials
app.get('/api/admin/materials', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const materials = await Material.find().sort({ uploadedAt: -1 });
    res.json(materials);
  } catch (error) { 
    console.error('Fetch materials error:', error.message);
    res.status(500).json({ message: 'Error fetching materials' }); 
  }
});

// Admin Delete Material (Path Traversal Hardened)
app.delete('/api/admin/delete-material/:id', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const materialId = req.params.id;
    const material = await Material.findById(materialId);
    if (!material) return res.status(404).json({ message: 'File record not found!' });

    if (material.fileUrl && material.fileUrl.includes('/uploads/')) {
      const filename = path.basename(material.fileUrl);
      const resolvedPath = path.resolve(UPLOADS_DIR, filename);

      if (resolvedPath.startsWith(UPLOADS_DIR + path.sep) || resolvedPath === UPLOADS_DIR) {
        try {
          if (fs.existsSync(resolvedPath)) {
            await fs.promises.unlink(resolvedPath);
          }
        } catch (fileErr) {
          console.error('File removal error from disk:', fileErr.message);
        }
      }
    }

    await Material.findByIdAndDelete(materialId);
    res.status(200).json({ message: '🗑️ Deleted successfully!' });
  } catch (error) { 
    console.error('Delete error:', error.message);
    res.status(500).json({ message: 'Server error during deletion' }); 
  }
});

// Dashboard Recent Materials Endpoint
app.get('/api/materials', checkDatabaseConnection, verifyToken, async (req, res) => {
  try {
    const materials = await Material.find().sort({ uploadedAt: -1 }).limit(30);
    res.json(materials);
  } catch (error) {
    console.error('Dashboard materials fetch error:', error.message);
    res.status(500).json({ message: 'Error fetching dashboard materials' });
  }
});

// Student Materials Endpoint by Course & Semester
app.get('/api/materials/:course/:semester', checkDatabaseConnection, verifyToken, async (req, res) => {
  try {
    const { course, semester } = req.params;
    const materials = await Material.find({ course: course.toLowerCase(), semester }).sort({ uploadedAt: -1 });
    res.json(materials);
  } catch (error) { 
    console.error('Materials fetch error:', error.message);
    res.status(500).json({ message: 'Data fetch error' }); 
  }
});

// Admin Get Student Logs
app.get('/api/admin/logs', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const logs = await Log.find().sort({ loginTime: -1 });
    res.json(logs);
  } catch (error) { 
    console.error('Logs fetch error:', error.message);
    res.status(500).json({ message: 'Logs fetch error' }); 
  }
});

// Admin Logout All Users
app.post('/api/admin/logout-all', checkDatabaseConnection, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const currentTime = new Date();
    await Log.updateMany(
      { logoutTime: { $exists: false } }, 
      { $set: { logoutTime: currentTime, durationInSeconds: 0 } }
    );
    res.status(200).json({ message: '🚀 All students logged out successfully!' });
  } catch (error) { 
    console.error('Logout all error:', error.message);
    res.status(500).json({ message: 'Server error during logout-all' }); 
  }
});

// Student Registration (Hardened)
app.post('/api/register', checkDatabaseConnection, async (req, res) => {
  try {
    const { name, mobile, password, course } = req.body;
    if (
      typeof name !== 'string' || !name.trim() ||
      typeof mobile !== 'string' || !/^[0-9]{10}$/.test(mobile) ||
      typeof password !== 'string' ||
      typeof course !== 'string'
    ) {
      return res.status(400).json({ message: '🛑 Invalid input format! Name, 10-digit mobile, and course required.' });
    }
    if (!isPasswordStrong(password)) {
      return res.status(400).json({ message: '🛑 Password must contain 8+ chars, 1 uppercase, 1 lowercase, 1 number, & 1 special char.' });
    }

    const userExists = await User.findOne({ mobile });
    if (userExists) return res.status(400).json({ message: 'This mobile number is already registered!' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ 
      name: name.trim(), 
      mobile, 
      password: hashedPassword, 
      course: course.toLowerCase(), 
      role: 'student' 
    });
    await newUser.save();

    res.status(201).json({ message: 'Registration successful!' });
  } catch (error) { 
    console.error('Registration error:', error.message);
    res.status(500).json({ message: 'Server error during registration' }); 
  }
});

// User Logout
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

// 🔑 Send OTP for Password Reset
app.post('/api/send-otp', authLimiter, checkDatabaseConnection, async (req, res) => {
  try {
    const { mobile } = req.body;
    if (typeof mobile !== 'string' || !/^[0-9]{10}$/.test(mobile)) {
      return res.status(400).json({ message: 'Please provide a valid 10-digit mobile number.' });
    }

    const user = await User.findOne({ mobile });
    if (!user) return res.status(404).json({ message: 'This mobile number is not registered!' });

    const otp = crypto.randomInt(100000, 999999).toString();
    setOtpWithExpiry(mobile, otp);

    if (process.env.NODE_ENV !== 'production') {
      console.log(`[DEV ONLY] OTP for ${mobile}: ${otp}`);
    }

    res.status(200).json({ message: 'OTP sent successfully!' });
  } catch (error) {
    console.error('Send OTP error:', error.message);
    res.status(500).json({ message: 'Error sending OTP' });
  }
});

// ✅ Verify OTP & Reset Password
app.post('/api/verify-otp-reset', authLimiter, checkDatabaseConnection, async (req, res) => {
  try {
    const { mobile, otp, newPassword } = req.body;

    if (typeof mobile !== 'string' || typeof otp !== 'string' || typeof newPassword !== 'string') {
      return res.status(400).json({ message: '🛑 Invalid input format!' });
    }

    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({ message: '🛑 Password must be 8+ chars with uppercase, lowercase, number, and special character.' });
    }

    const storedOtp = getStoredOtp(mobile);
    if (!storedOtp || storedOtp !== otp) {
      return res.status(400).json({ message: 'Incorrect or expired OTP!' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await User.findOneAndUpdate({ mobile }, { password: hashedPassword });

    const entry = otpStore.get(mobile);
    if (entry) {
      clearTimeout(entry.timer);
      otpStore.delete(mobile);
    }

    res.status(200).json({ message: 'Password reset successfully!' });
  } catch (error) {
    console.error('Reset password error:', error.message);
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