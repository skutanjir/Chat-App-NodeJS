const express = require('express');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const http = require('http');
const socketIO = require('socket.io');

// Inisialisasi aplikasi
const app = express();
const server = http.createServer(app);
const io = socketIO(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3001;
const SECRET_KEY = 'your_jwt_secret'; // Ubah ini dengan kunci yang aman

// Middleware setup
app.use(cors({
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:5173',           // URL lokal frontend
            'https://7fd0-114-79-20-204.ngrok-free.app' // URL dari ngrok atau domain frontend lainnya
        ];
        if (!origin) return callback(null, true); // Izinkan Postman atau server to server
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true 
}));
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads')); // Serve static files from "uploads" directory

// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Ensure unique filenames
    }
});
const upload = multer({ storage: storage });

// Setup koneksi MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'chatsapp'
});

db.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('MySQL connected');
});

// Middleware untuk otentikasi JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Register route
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], (err) => {
        if (err) {
            console.error('Error registering new user:', err);
            return res.status(500).send('Error registering new user');
        }
        res.status(201).send('User registered');
    });
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT id, password FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).send('Error fetching user');
        }
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid credentials');
        }
        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Send Friend Request
app.post('/friend-request', authenticateToken, (req, res) => {
    const { friendEmail } = req.body;
    const senderId = req.user.id;

    db.query('SELECT id FROM users WHERE email = ?', [friendEmail], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send('User not found');
        }
        const friendId = results[0].id;

        if (friendId === senderId) {
            return res.status(400).send("Can't send friend request to oneself");
        }

        db.query('SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', 
        [senderId, friendId, friendId, senderId], (err, results) => {
            if (err) return res.status(500).send('Database error');
            if (results.length > 0) return res.status(400).send('Friend request already sent or received');

            db.query('INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, "pending")', [senderId, friendId], (err) => {
                if (err) return res.status(500).send('Error sending friend request');
                res.send('Friend request sent');
            });
        });
    });
});

// Accept Friend Request
app.post('/accept-friend-request', authenticateToken, (req, res) => {
    const { senderId } = req.body;
    const userId = req.user.id;

    db.query('UPDATE friends SET status = "accepted" WHERE user_id = ? AND friend_id = ? AND status = "pending"', 
    [senderId, userId], (err, results) => {
        if (err) return res.status(500).send('Error accepting friend request');
        if (results.affectedRows === 0) return res.status(404).send('Friend request not found');
        res.send('Friend request accepted');
    });
});

// Decline Friend Request
app.post('/decline-friend-request', authenticateToken, (req, res) => {
    const { senderId } = req.body;
    const userId = req.user.id;

    db.query('DELETE FROM friends WHERE user_id = ? AND friend_id = ? AND status = "pending"', 
    [senderId, userId], (err, results) => {
        if (err) return res.status(500).send('Error declining friend request');
        if (results.affectedRows === 0) return res.status(404).send('Friend request not found');
        res.send('Friend request declined');
    });
});

// Rute untuk mengambil pesan antara user dan teman tertentu
app.get('/messages/:friendId', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const friendId = req.params.friendId;

    db.query(`
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) 
        OR (sender_id = ? AND receiver_id = ?) 
        ORDER BY timestamp ASC`, 
    [userId, friendId, friendId, userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching messages');
        res.json(results); 
    });
});

// Get Friend Requests
app.get('/friend-requests', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT users.id AS sender_id, users.email FROM users JOIN friends ON users.id = friends.user_id WHERE friends.friend_id = ? AND friends.status = "pending"', 
    [userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching friend requests');
        res.json(results);
    });
});

// Get Friends List
app.get('/friends', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT users.id, users.email FROM users JOIN friends ON (users.id = friends.user_id OR users.id = friends.friend_id) WHERE (friends.user_id = ? OR friends.friend_id = ?) AND friends.status = "accepted" AND users.id != ?', 
    [userId, userId, userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching friends list');
        res.json(results);
    });
});

// Remove Friend
app.post('/remove-friend', authenticateToken, (req, res) => {
    const { friendId } = req.body;
    const userId = req.user.id;

    db.query('DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', 
    [userId, friendId, friendId, userId], (err, results) => {
        if (err) return res.status(500).send('Error removing friend');
        res.send('Friend removed');
    });
});

// Rute untuk mengirim pesan ke teman tertentu dengan file handling (image/video)
app.post('/send-message', authenticateToken, upload.single('file'), (req, res) => {
    const { receiverId, message } = req.body;
    const senderId = req.user.id;
    const fileUrl = req.file ? `/uploads/${req.file.filename}` : null;

    // Simpan pesan ke database
    db.query('INSERT INTO messages (sender_id, receiver_id, message, file_url) VALUES (?, ?, ?, ?)', 
    [senderId, receiverId, message, fileUrl], (err, results) => {
        if (err) return res.status(500).send('Error sending message');
        
        // Memancarkan pesan melalui socket ke room yang relevan
        io.to(receiverId).emit('chat message', {
            sender_id: senderId,
            receiver_id: receiverId,
            message,
            timestamp: new Date(),
            file_url: fileUrl
        });

        res.send('Message sent');
    });
});

// Handle typing indicator events
io.on('connection', (socket) => {
    console.log('A user connected', socket.id);

    socket.on('join', (userId) => {
        socket.join(userId); // Bergabung dengan room berdasarkan userId
        console.log(`User with ID ${userId} joined room`);
    });

    // Typing event
    socket.on('typing', (data) => {
        io.to(data.receiver_id).emit('typing', {
            sender_id: data.sender_id,
            receiver_id: data.receiver_id
        });
    });

    // Stop typing event
    socket.on('stop typing', (data) => {
        io.to(data.receiver_id).emit('stop typing', {
            sender_id: data.sender_id,
            receiver_id: data.receiver_id
        });
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected', socket.id);
    });
});

// Start server
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});



