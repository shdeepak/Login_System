require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const authRoutes = require('./routes/auth');

const app = express();

app.use(express.static('public'));
app.use(cors());
app.use(express.json());

// Simple MongoDB connection without deprecated options
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

app.use('/api/auth', authRoutes);

app.listen(5000, () => console.log('🚀 Server running on port 5000'));
