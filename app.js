const express = require('express');
const app = express();
const cors = require('cors');
app.use(cors());
const mongoose = require("mongoose");
const port = process.env.PORT || 5000;
app.use(express.json());
require('dotenv').config();

// Connecting to MongoDB
const db_link = process.env.MONGO_URI
mongoose.connect(db_link)
    .then(() => {
        console.log('db_connected');
        // insertDummyData(); // Insert dummy data after DB connection
    })
    .catch(err => console.log(err));

// Creating User schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});
const UserData = mongoose.model("DigiUsers", userSchema);

// Creating Device schema
const deviceSchema = new mongoose.Schema({
    deviceName: String,
    deviceType: String,
    status: { type: String, default: "offline" },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "DigiUsers" } // Reference to the user who owns the device
});
const Device = mongoose.model("Devices", deviceSchema);
// Creatinng the result Schema
const resultSchema= new mongoose.Schema({
    name:String,
    opticalResolution:String,
    iss:String,
    concentration:String,
    brix:String,
    ploPercent:String,
    purity:String,
    date:String,

});
const DeviceResult = mongoose.model("result",resultSchema);

// Define a route
app.get('/', (req, res) => {
    res.send('Hello World!');
});

// Register User
app.post('/register', async (req, res) => {
    try {
        const newUser = new UserData(req.body);  // Create a new user from request body
        await newUser.save();  // Save the new user to MongoDB
        res.status(201).json({ message: "User created successfully", user: newUser });
    } catch (err) {
        res.status(400).json({ error: 'Error creating user', details: err.message });
    }
});

// Login User
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    UserData.findOne({ email: email })
        .then(user => {
            if (user) {
                // Check if password matches
                if (user.password === password) {
                    res.json({ message: "Success", userId: user._id , userName:user.name});  // Send userId to frontend
                } else {
                    res.json({ message: "The password is incorrect" });
                }
            } else {
                res.json({ message: "No user exists" });
            }
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ message: "Error finding user" });
        });
});

// Add Device for a User
app.post('/api/user/devices/:userId', async (req, res) => {
    try {
        const { userId } = req.params; // Get userId from request parameters
        const newDevice = new Device({ ...req.body, userId });  // Create a new device with userId
        await newDevice.save();  // Save the device to MongoDB
        res.status(201).json({ success: "Device added successfully", device: newDevice });
    } catch (err) {
        res.status(400).json({ error: 'Error adding device', details: err.message });
    }
});

app.post('/api/user/devices/:name', async (req, res) => {
    const {  name } = req.params;
});
// Fetch Devices for a Specific User
app.get('/api/user/devices/:id', async (req, res) => {
    const userId = req.params.id;  // Extract userId from the route parameter

    try {
        const devices = await Device.find({ userId: userId });  // Find devices for the user
        res.json(devices);
    } catch (error) {
        res.status(500).json({ message: "Unable to fetch devices" });
    }
});


// Route to insert 10 manual DeviceResult records


// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
