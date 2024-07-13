import { Hono } from 'hono';
import { jwt, decode, sign, verify } from 'hono/jwt';
import { createToken, validateAccess } from './middleware';
import { getCookie, setCookie } from 'hono/cookie';

const bcrypt = require('bcryptjs');

type Env = {
	DB: D1Database;
	REFRESH_TOKEN_SECRET: string;
	ACCESS_TOKEN_SECRET: string;
};

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
