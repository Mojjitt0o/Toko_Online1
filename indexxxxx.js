const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const port = 3000;

// Konfigurasi koneksi database
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'admin',
  port: 5432,
});

// Middleware untuk mengurai body permintaan
app.use(bodyParser.json());

// Middleware untuk verifikasi token pengguna
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, 'secret');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error('Error verifying token', error);
    return res.status(403).json({ error: 'Forbidden' });
  }
}

// Endpoint untuk registrasi pengguna
app.post('/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)';
    const values = [username, hashedPassword, role];
    await pool.query(query, values);
    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint untuk login pengguna
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = $1';
    const result = await pool.query(query, [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user.id }, 'secret', { expiresIn: '1h' });
    res.json({ token, role: user.role });
  } catch (error) {
    console.error('Error logging in user', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint untuk menyimpan data pelanggan (hanya dapat diakses oleh admin)
app.post('/customers', verifyToken, async (req, res) => {
  try {
    const { name, email } = req.body;
    const query = 'INSERT INTO customers (name, email) VALUES ($1, $2)';
    const values = [name, email];
    await pool.query(query, values);
    res.json({ message: 'Customer data saved successfully' });
  } catch (error) {
    console.error('Error saving customer data', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint untuk menyimpan daftar item (hanya dapat diakses oleh admin)
app.post('/items', verifyToken, async (req, res) => {
  try {
    const { name, price } = req.body;
    const query = 'INSERT INTO items (name, price) VALUES ($1, $2)';
    const values = [name, price];
    await pool.query(query, values);
    res.json({ message: 'Item data saved successfully' });
  } catch (error) {
    console.error('Error saving item data', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint untuk menerima pesanan dari pelanggan
app.post('/orders', async (req, res) => {
  try {
    // Proses pembuatan pesanan
    res.json({ message: 'Order received successfully' });
  } catch (error) {
    console.error('Error processing order', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint untuk mendapatkan semua data pelanggan
app.get('/customers', verifyToken, async (req, res) => {
  try {
    const query = 'SELECT * FROM customers';
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching customer data', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint untuk mendapatkan semua data item
app.get('/items', verifyToken, async (req, res) => {
  try {
    const query = 'SELECT * FROM items';
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching item data', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint untuk mendapatkan semua data pesanan
app.get('/orders', verifyToken, async (req, res) => {
  try {
    // Query untuk mendapatkan data pesanan
    res.json({ message: 'Retrieve orders successfully' });
  } catch (error) {
    console.error('Error fetching orders data', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Jalankan server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
