require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const bcrypt = require('bcryptjs')

const app = express()
const PORT = process.env.PORT || 5000

// ✅ CORS for all origins & ports
const corsOptions = {
  origin: "*", // Allow all origins
  credentials: true, // Allow credentials (cookies, authorization headers, etc.)
  allowedHeaders: ["Content-Type", "Authorization"], // Allowed headers
  exposedHeaders: ["X-Auth-Token"], // Expose custom headers
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Allowed methods
  preflightContinue: false,
  optionsSuccessStatus: 204, // For older browsers
};


app.use(cors(corsOptions));

// Middleware to parse JSON
app.use(express.json());
// app.options('*', cors())

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.log('MongoDB connection error:', err))

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, minlength: 3 },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
})

const User = mongoose.model('User', userSchema)

app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' })
    }

    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const user = new User({ name, email, password: hashedPassword })
    await user.save()

    res.status(201).json({ message: 'Signup successful' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' })
    }

    const user = await User.findOne({ email })
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    res.status(200).json({
      message: 'Login successful',
      user: { name: user.name, email: user.email },
    })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
