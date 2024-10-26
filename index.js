const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();

// JWT Secret Key
const JWT_SECRET = 'Super_secret_key_beyazpolis_f44141414'; // Replace with a strong, dont replace!, unique secret key

// Middleware
app.use(express.json());

// Multer setup for file uploads
const uploadDir = path.join(__dirname, 'uploads');

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  }
});

const upload = multer({ storage: storage });

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/cw-users')
  .then(() => console.log("Connection successful!"))
  .catch((err) => console.error(err));

// User model
const User = mongoose.model('User', {
  username: String,
  password: String,
  isAdmin: Boolean
});

// Worker model
const Worker = mongoose.model('Worker', {
  username: String,
  dailyLogs: [{
    date: { type: Date, default: Date.now },
    clockIns: [{
      clockInTime: Date,
      selfiePath: String,
      gpsLocations: [{ lat: Number, lon: Number }],
    }],
    clockOuts: [{
      clockOutTime: Date,
      selfiePath: String,
      gpsLocations: { lat: Number, lon: Number },
    }],
    lunchBreaks: [{
      lunchStartTime: Date,
      lunchEndTime: Date
    }],
    status: { type: Number, default: 0 }, // 0: clocked out, 1: working, 2: lunch break
    workDurationInSeconds: { type: Number, default: 0 } // Toplam çalışma süresi (saniye cinsinden)
  }],
});


// Middleware: Token verification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  console.log('Auth Header:', authHeader);

  const token = authHeader && authHeader.split(' ')[1];
  console.log('Extracted Token:', token);

  if (token == null) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Decoded Token:', decoded);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification failed:', error.message);
    return res.status(403).json({ error: 'Invalid token', details: error.message });
  }
};

// Middleware: Admin check
const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin) return res.sendStatus(403);
  next();
};

// Clock-out route with updated work hours calculation
app.post('/clock-out', authenticateToken, upload.single('selfie'), async (req, res) => {
  const { username, gpsLocation } = req.body;

  if (!req.file) {
    return res.status(400).send('Selfie is required');
  }

  try {
    const parsedGpsLocation = JSON.parse(gpsLocation);

    const worker = await Worker.findOne({ username });
    if (!worker) {
      return res.status(404).send('Worker not found');
    }

    const today = new Date().setHours(0, 0, 0, 0);

    const dailyLog = worker.dailyLogs.find(log => 
      new Date(log.date).setHours(0, 0, 0, 0) === today
    );

    if (!dailyLog || dailyLog.status === 0) {
      return res.status(400).send('Worker is not clocked in today');
    }

    dailyLog.clockOuts.push({
      clockOutTime: new Date(),
      selfiePath: req.file.path,
      gpsLocations: {
        lat: parsedGpsLocation.lat,
        lon: parsedGpsLocation.lon
      }
    });

    dailyLog.status = 0; // Set status to clocked out

    await worker.save();
    
    // Calculate work hours for current day
    const workHours = dailyLog.clockOuts.reduce((total, clockOut, index) => {
      if (dailyLog.clockIns[index]) {
        return total + (clockOut.clockOutTime - dailyLog.clockIns[index].clockInTime) / (1000 * 60 * 60);
      }
      return total;
    }, 0);

    // Calculate lunch hours for current day
    const lunchHours = dailyLog.lunchBreaks.reduce((total, break_) => {
      if (break_.lunchEndTime) {
        return total + (break_.lunchEndTime - break_.lunchStartTime) / (1000 * 60 * 60);
      }
      return total;
    }, 0);

    res.status(200).json({
      message: 'Clock-out successful',
      dailyWorkHours: workHours,
      dailyLunchHours: lunchHours
    });
  } catch (error) {
    console.error('Clock-out error:', error);
    res.status(500).send('Clock-out failed');
  }
});

// Lunch toggle route with updated status
app.post('/lunch-toggle', async (req, res) => {
  const { username } = req.body;

  try {
    const worker = await Worker.findOne({ username });

    if (!worker) {
      return res.status(404).json({ message: 'Worker not found' });
    }

    const today = new Date();
    const dailyLog = worker.dailyLogs.find(log => log.date.toDateString() === today.toDateString());

    if (!dailyLog) {
      return res.status(404).json({ message: 'Daily log not found' });
    }

    if (dailyLog.status === 2) {
      // If on lunch, end lunch break
      dailyLog.status = 1; // Back to working
      const lunchEndTime = new Date();
      dailyLog.lunchBreaks[dailyLog.lunchBreaks.length - 1].lunchEndTime = lunchEndTime;
    } else if (dailyLog.status === 1) {
      // If working, start lunch break
      dailyLog.status = 2; // Set to lunch break
      dailyLog.lunchBreaks.push({ lunchStartTime: new Date(), lunchEndTime: null });
    } else {
      return res.status(400).json({ message: 'Worker must be clocked in to take a lunch break' });
    }

    await worker.save();

    // Calculate current day's lunch hours
    const lunchHours = dailyLog.lunchBreaks.reduce((total, break_) => {
      if (break_.lunchEndTime) {
        return total + (break_.lunchEndTime - break_.lunchStartTime) / (1000 * 60 * 60);
      }
      return total;
    }, 0);

    return res.status(200).json({ 
      message: dailyLog.status === 2 ? 'Lunch started successfully' : 'Lunch ended successfully',
      status: dailyLog.status,
      dailyLunchHours: lunchHours
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error', error });
  }
});
// Login route
app.post('/login', async (req, res) => {
  console.log('Login attempt:', req.body.username);
  const user = await User.findOne({ username: req.body.username });
  
  if (!user) {
    console.log('User not found');
    return res.status(400).send('User not found');
  }

  // Compare passwords directly instead of using bcrypt
  const isPasswordValid = req.body.password === user.password;
  if (!isPasswordValid) {
    console.log('Invalid password');
    return res.status(400).send('Invalid credentials');
  }

  const token = jwt.sign({ username: user.username, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '999999h' });
  console.log('Login successful');
  res.json({ token });
});

// Register route (admin only)
app.post('/register', authenticateToken, isAdmin, async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const newUser = new User({ username: req.body.username, password: hashedPassword, isAdmin: false });
  await newUser.save();
  res.status(201).send('User created');
});

// Delete worker route
app.delete('/workers/:username', authenticateToken, isAdmin, async (req, res) => {
  const { username } = req.params;

  try {
    const userResult = await User.findOneAndDelete({ username: username });
    const workerResult = await Worker.findOneAndDelete({ username: username });

    if (!userResult && !workerResult) {
      return res.status(404).json({ message: 'User and Worker not found' });
    } else if (!userResult) {
      return res.status(404).json({ message: 'User not found' });
    } else if (!workerResult) {
      return res.status(404).json({ message: 'Worker not found' });
    }

    res.status(200).json({ message: 'User and Worker deleted successfully' });
  } catch (error) {
    console.error('Error deleting user and worker:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create worker route
app.post('/workers', authenticateToken, async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingWorker = await Worker.findOne({ username });
    const existingUser = await User.findOne({ username });

    if (existingWorker || existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const newUser = new User({
      username: username,
      password: password,
      isAdmin: false
    });
    await newUser.save();

    const newWorker = new Worker({
      username: username,
      dailyLogs: []
    });
    await newWorker.save();

    res.status(201).json({ message: 'Worker and account created successfully' });
  } catch (error) {
    console.error('Error creating worker:', error);
    try {
      await User.deleteOne({ username: username });
      await Worker.deleteOne({ username: username });
    } catch (rollbackError) {
      console.error('Rollback error:', rollbackError);
    }
    res.status(500).json({ 
      message: 'Error creating worker and account',
      error: error.message 
    });
  }
});

// Get single worker route
app.get('/worker', async (req, res) => {
  const { username } = req.query;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    const worker = await Worker.findOne({ username: username });

    if (!worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }

    res.status(200).json(worker);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// List workers route
app.get('/workers', authenticateToken, async (req, res) => {
  const workers = await Worker.find();
  res.json(workers);
});

// Clock-in route
app.post('/clock-in', authenticateToken, upload.single('selfie'), async (req, res) => {
  const { username, gpsLocation } = req.body;

  try {
    // Input validation
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'Selfie is required'
      });
    }

    if (!gpsLocation) {
      return res.status(400).json({
        success: false,
        message: 'GPS location is required'
      });
    }

    // Parse GPS location
    let parsedGpsLocation;
    try {
      parsedGpsLocation = JSON.parse(gpsLocation);
      if (!parsedGpsLocation.lat || !parsedGpsLocation.lon) {
        throw new Error('Invalid GPS format');
      }
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid GPS location format'
      });
    }

    // Find worker
    const worker = await Worker.findOne({ username });
    if (!worker) {
      return res.status(404).json({
        success: false,
        message: 'Worker not found'
      });
    }

    // Check if worker is already clocked in
    const today = new Date().setHours(0, 0, 0, 0);
    let dailyLog = worker.dailyLogs.find(log => 
      new Date(log.date).setHours(0, 0, 0, 0) === today
    );

    if (dailyLog && dailyLog.status === 1) {
      return res.status(400).json({
        success: false,
        message: 'Worker is already clocked in'
      });
    }

    // Create new daily log if doesn't exist
    if (!dailyLog) {
      dailyLog = {
        date: new Date(),
        clockIns: [],
        clockOuts: [],
        lunchBreaks: [],
        status: 1 // 1 represents working status
      };
      worker.dailyLogs.push(dailyLog);
    } else {
      dailyLog.status = 1; // Update status to working
    }

    // Add clock-in entry
    const clockInEntry = {
      clockInTime: new Date(),
      selfiePath: req.file.path,
      gpsLocations: [{
        lat: parsedGpsLocation.lat,
        lon: parsedGpsLocation.lon
      }]
    };

    dailyLog.clockIns.push(clockInEntry);

    // Save changes
    await worker.save();

    // Return success response
    return res.status(200).json({
      success: true,
      message: 'Clock-in successful',
      data: {
        clockInTime: clockInEntry.clockInTime,
        location: clockInEntry.gpsLocations[0]
      }
    });

  } catch (error) {
    console.error('Clock-in error:', error);
    
    // Delete uploaded file if exists and operation failed
    if (req.file) {
      try {
        await fs.unlink(req.file.path);
      } catch (unlinkError) {
        console.error('Error deleting file:', unlinkError);
      }
    }

    return res.status(500).json({
      success: false,
      message: 'Internal server error during clock-in'
    });
  }
});

// GPS verification route
app.post('/gps-verification', authenticateToken, async (req, res) => {
  const { username, gpsLocation } = req.body;

  try {
    const parsedGpsLocation = JSON.parse(gpsLocation);

    console.log(username);
    const worker = await Worker.findOne({ username });
    if (!worker) {
      return res.status(404).send('Worker not found');
    }

    const today = new Date().setHours(0, 0, 0, 0); // Set to midnight for date comparison only

    // Find today's log
    const dailyLog = worker.dailyLogs.find(log => 
      new Date(log.date).setHours(0, 0, 0, 0) === today
    );

    if (!dailyLog) {
      return res.status(400).send('No clock-in record found for today');
    }

    if (dailyLog.status !== 1) {
      return res.status(400).send('Worker must be clocked in to verify GPS location');
    }

    dailyLog.workDurationInSeconds += 60; // Artış yap
    // Save the updated worker document
    await worker.save();

    res.status(200).json({
      message: 'GPS verification successful',
    });
  } catch (error) {
    console.error('GPS verification error:', error);
    res.status(500).send('GPS verification failed');
  }
});

// Get weekly report route
app.get('/weekly-report', authenticateToken, async (req, res) => {
  const { username, startDate } = req.query;

  try {
    const worker = await Worker.findOne({ username });
    if (!worker) {
      return res.status(404).send('Worker not found');
    }

    const start = startDate ? new Date(startDate) : new Date();
    start.setHours(0, 0, 0, 0);
    
    const end = new Date(start);
    end.setDate(end.getDate() + 7);

    const weeklyLogs = worker.dailyLogs.filter(log => {
      const logDate = new Date(log.date);
      return logDate >= start && logDate < end;
    });

    const report = {
      startDate: start,
      endDate: end,
      totalWorkHours: weeklyLogs.reduce((total, log) => total + (log.totalWorkHours || 0), 0),
      totalLunchHours: weeklyLogs.reduce((total, log) => total + (log.totalLunchHours || 0), 0),
      dailyBreakdown: weeklyLogs.map(log => ({
        date: log.date,
        workHours: log.totalWorkHours || 0,
        lunchHours: log.totalLunchHours || 0,
        clockIns: log.clockIns.length,
        clockOuts: log.clockOuts.length
      }))
    };

    res.status(200).json(report);
  } catch (error) {
    console.error('Error generating weekly report:', error);
    res.status(500).send('Failed to generate weekly report');
  }
});

// Get monthly report route
app.get('/monthly-report', authenticateToken, async (req, res) => {
  const { username, month, year } = req.query;

  try {
    const worker = await Worker.findOne({ username });
    if (!worker) {
      return res.status(404).send('Worker not found');
    }

    const startDate = new Date(year, month - 1, 1);
    const endDate = new Date(year, month, 0);

    const monthlyLogs = worker.dailyLogs.filter(log => {
      const logDate = new Date(log.date);
      return logDate >= startDate && logDate <= endDate;
    });

    const report = {
      month: month,
      year: year,
      totalWorkHours: monthlyLogs.reduce((total, log) => total + (log.totalWorkHours || 0), 0),
      totalLunchHours: monthlyLogs.reduce((total, log) => total + (log.totalLunchHours || 0), 0),
      daysWorked: monthlyLogs.length,
      averageWorkHoursPerDay: monthlyLogs.length > 0 ? 
        monthlyLogs.reduce((total, log) => total + (log.totalWorkHours || 0), 0) / monthlyLogs.length : 0,
      averageLunchHoursPerDay: monthlyLogs.length > 0 ?
        monthlyLogs.reduce((total, log) => total + (log.totalLunchHours || 0), 0) / monthlyLogs.length : 0,
      dailyBreakdown: monthlyLogs.map(log => ({
        date: log.date,
        workHours: log.totalWorkHours || 0,
        lunchHours: log.totalLunchHours || 0,
        clockIns: log.clockIns.length,
        clockOuts: log.clockOuts.length
      }))
    };

    res.status(200).json(report);
  } catch (error) {
    console.error('Error generating monthly report:', error);
    res.status(500).send('Failed to generate monthly report');
  }
});

app.get('/check-admin', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    
    if (!user) {
      return res.status(404).json({ isAdmin: false, message: 'User not found' });
    }

    res.json({ isAdmin: user.isAdmin });
  } catch (error) {
    console.error('Error checking admin status:', error);
    res.status(500).json({ isAdmin: false, message: 'Internal server error' });
  }
});


// Function to create admin accounts
// Function to create admin accounts and corresponding worker accounts
async function createAdminAccounts() {
  try {
    const existingAdmin = await User.findOne({ username: "gremlin"});
    if (!existingAdmin) {
      const newAdmin = new User({
        username: "gremlin",
        password: "cw5941admin", // Password stored as plain text as requested
        isAdmin: true
      });
      await newAdmin.save();
      console.log(`Admin account created: gremlin`);

      // Create corresponding worker account
      const newWorker = new Worker({
        username: "gremlin",
        dailyLogs: [] // Empty daily logs initially
      });
      await newWorker.save();
      console.log(`Worker account created: gremlin`);
    } else {
      console.log(`Admin account already exists: gremlin`);
    }
  } catch (error) {
    console.error(`Error creating admin account gremlin:`, error);
  }
}

// Call the function when the application starts
createAdminAccounts();


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));