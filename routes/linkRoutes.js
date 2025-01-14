import { Router } from 'express';
import { authenticateToken } from '../server.js';

const router = Router();

const linkRoutes = (db) => {
    router.get('/', (req, res) => {
        db.all(
            'SELECT * FROM links ORDER BY createdAt DESC',
            (err, links) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json(links);
            }
        );
    });


    router.get('/:id', authenticateToken, (req, res) => {
        db.get(
            'SELECT * FROM links WHERE id = ? AND userId = ?',
            [req.params.id, req.user.id],
            (err, link) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                if (!link) {
                    return res.status(404).json({ error: 'Link not found' });
                }
                res.json(link);
            }
        );
    });

    router.post('/:userId', authenticateToken, (req, res) => {

        const { title, link, category, description } = req.body;
        const userId = parseInt(req.params.userId); // Get userId from params
        
        if (!title || !link) {
            return res.status(400).json({ error: 'Title and link are required' });
        }

        // Optional: Check if the userId from params matches the authenticated user's id
        if (userId !== req.user.id) {
            return res.status(403).json({ error: 'Unauthorized: Cannot create links for other users' });
        }

        db.run(
            'INSERT INTO links (userId, title, link, category, description) VALUES (?, ?, ?, ?, ?)',
            [userId, title, link, category, description || ''],
            function (err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                res.status(201).json({
                    id: this.lastID,
                    title,
                    link,
                    category,
                    description,
                    userId
                });
            }
        );
    });

    router.put('/:id', authenticateToken, (req, res) => {
        const { title, link, category, description } = req.body;

        if (!title || !link) {
            return res.status(400).json({ error: 'Title and link are required' });
        }

        db.run(
            'UPDATE links SET title = ?, link = ?, category = ?, description = ? WHERE id = ? AND userId = ?',
            [title, link, category, description || '', req.params.id, req.user.id],
            function (err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                if (this.changes === 0) {
                    return res.status(404).json({ error: 'Link not found or unauthorized' });
                }

                res.json({
                    id: parseInt(req.params.id),
                    title,
                    link,
                    category,
                    description,
                    userId: req.user.id
                });
            }
        );
    });

    return router;
};

export default linkRoutes;
