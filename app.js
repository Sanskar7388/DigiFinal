const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// const allowedOrigins = [
//     'http://localhost:3000',  // Development origin
//     'https://myapp.com'       // Production origin
// ];

app.use(cors({
    origin:'http://localhost:3000',
    credentials: true
}));

 
// Allow credentials for cross-origin requests
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('db_connected'))
    .catch(err => console.log(err));

// User schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});
const UserData = mongoose.model("DigiUsers", userSchema);

// Device schema
const deviceSchema = new mongoose.Schema({
    deviceName: String,
    deviceType: String,
    status: { type: String, default: "offline" },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "DigiUsers" }
});
const Device = mongoose.model("Devices", deviceSchema);

// Middleware to authenticate JWT from cookies
const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token; // Get the token from cookies

    if (!token) return res.status(401).json({ message: "Access denied" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ message: "Invalid token" });
    }
};

// Register User
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if the email already exists
        const existingUser = await UserData.findOne({ email });
        if (existingUser) {
            return res.json({ message: "Email already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user with hashed password
        const newUser = new UserData({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        res.status(500).json({ error: 'Error creating user', details: err.message });
    }
});


// Login User and set JWT in cookie
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await UserData.findOne({ email });

        if (user && await bcrypt.compare(password, user.password)) {
            // Generate a JWT token
            const token = jwt.sign({ userId: user._id, userName: user.name }, JWT_SECRET, { expiresIn: '1h' });

            // Set the token in a cookie
            res.cookie('token', token, {
                httpOnly: true,  // Prevent access to the cookie via JavaScript
                secure: true, 
                sameSite: 'None',
                maxAge: 60 * 60 * 1000 // 1 hour
            });

            res.json({ message: "Success" , userName:user.name });
        } else {
            res.status(401).json({ message: "Invalid email or password" });
        }
    } catch (err) {
        res.status(500).json({ message: "Error logging in", details: err.message });
    }
});

// Logout User - Clear the token cookie
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: "Logged out successfully" });
});

// Protected route to add device for a user
app.post('/api/user/devices/', authenticateJWT, async (req, res) => {
    try {
        const  userId  = req.user.userId;
       
        const newDevice = new Device({ ...req.body, userId });
        await newDevice.save();
        res.status(201).json({ success: "Device added successfully", device: newDevice });
    } catch (err) {
        res.status(400).json({ error: 'Error adding device', details: err.message });
    }
});

// Protected route to fetch devices for a specific user
app.get('/api/user/devices', authenticateJWT, async (req, res) => {
    const userId = req.user.userId;  // Extract userId from decoded JWT

    try {
        const devices = await Device.find({ userId });
        res.json(devices);
    } catch (error) {
        res.status(500).json({ message: "Unable to fetch devices" });
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
