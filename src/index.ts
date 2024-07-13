import { Hono } from 'hono';
import { createToken, validateAccess } from './middleware';
import { getCookie, setCookie } from 'hono/cookie';

const bcrypt = require('bcryptjs');

type Env = {
	DB: D1Database;
	REFRESH_TOKEN_SECRET: string;
	ACCESS_TOKEN_SECRET: string;
};

interface User {
	id: number;
	username: string;
	email: string | null;
	password: string;
	created_at: string;
}

const app = new Hono<{ Bindings: Env }>();

app.post('/signup', async (c) => {
	const data = await c.req.json();
	const tokens = await createToken(data, c.env);
	const { accessToken, refreshToken } = tokens;

	const hashPassword = await bcrypt.hash(data.password, 8);
	const createUser = await c.env.DB.prepare('INSERT INTO users (username, password) VALUES (?, ?)').bind(data.username, hashPassword).run();
	if (!createUser) return c.json({ error: 'Error creating user' }, 500);

	const setToken = await c.env.DB.prepare('INSERT INTO tokens (user_id, token) VALUES (?, ?)')
		.bind(createUser.meta.last_row_id, refreshToken)
		.run();
	if (!setToken) return c.json({ error: 'Error creating token' }, 500);

	setCookie(c, 'refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
	return c.json({ accessToken });
});

app.post('/login', async (c) => {
	const data = await c.req.json();
	const tokens = await createToken(data, c.env);
	const { accessToken, refreshToken } = tokens;

	const user = (await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(data.username).run()) as D1Result<User>;
	if (user.results.length === 0) return c.json({ error: 'User not found' }, 404);

	const validPassword = await bcrypt.compare(data.password, user.results[0].password);
	if (!validPassword) return c.json({ error: 'Invalid password' }, 401);

	const setToken = await c.env.DB.prepare('INSERT INTO tokens (user_id, token) VALUES (?, ?)').bind(user.results[0].id, refreshToken).run();
	if (!setToken) return c.json({ error: 'Error creating token' }, 500);

	setCookie(c, 'refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
	return c.json({ accessToken });
});

// Friends/Game Requests
app.post('/requests', validateAccess, async (c) => {});

// Create Game
app.post('/games', validateAccess, async (c) => {});

// Create Player
app.post('/players', validateAccess, async (c) => {});

// Create Trade
app.post('/trades', validateAccess, async (c) => {});

export default app;
