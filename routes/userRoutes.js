import { Router } from 'express';
import { authenticateToken } from '../server.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const router = Router();

const userRoutes = (db) => {

    router.get('/test', (req, res) => {
        res.send('yo in here works.');
    });

    router.get('/profile', authenticateToken, (req, res) => {
        db.get('SELECT id, username, email, created_at FROM users WHERE id = ?',
            [req.user.id],
            (err, user) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                res.json(user);
            }
        );
    });

    router.get('/search', (req, res) => {
        const searchString = req.query.searchtext;

        if (!searchString) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        // Use LIKE with wildcards for partial matches
        // Using LOWER() to make the search case-insensitive
        const searchQuery = `
          SELECT id, username, fullName, email, created_at 
          FROM users 
          WHERE LOWER(username) LIKE LOWER(?) 
          OR LOWER(fullName) LIKE LOWER(?)
          ORDER BY username ASC
        `;

        const searchPattern = `%${searchString}%`;

        db.all(searchQuery, [searchPattern, searchPattern], (err, users) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            const safeUsers = users.map(user => ({
                id: user.id,
                username: user.username,
                fullName: user.fullName,
                created_at: user.created_at
            }));

            res.json(safeUsers);
        });
    });

    router.post('/login', (req, res) => {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                userId: user.id,
                token,
                username: user.username,
                fullName: user.fullName,
            });
        });
    });


    router.post('/signup', async (req, res) => {
        const { username, fullName, email, password } = req.body;

        // Validate input fields
        if (!username || !fullName || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        try {
            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert the new user into the database
            db.run(
                'INSERT INTO users (username, fullname, email, password) VALUES (?, ?, ?, ?)',
                [username, fullName, email, hashedPassword],
                function (err) {
                    if (err) {
                        // Handle unique constraint error for username/email
                        if (err.message.includes('UNIQUE constraint failed')) {
                            return res.status(400).json({ error: 'Username or email already exists' });
                        }
                        // Handle other database errors
                        return res.status(500).json({ error: err.message });
                    }

                    // Retrieve the last inserted ID
                    const userId = this.lastID;

                    // Generate a JWT token
                    const token = jwt.sign(
                        { id: userId, username },
                        process.env.JWT_SECRET,
                        { expiresIn: '24h' }
                    );

                    // Return the user details and token
                    res.status(201).json({ userId, token, username, fullName });
                }
            );
        } catch (err) {
            // Handle server-side errors
            res.status(500).json({ error: err.message });
        }
    });

    return router;
};

export default userRoutes;
