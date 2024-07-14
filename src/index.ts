import { Hono } from 'hono';
import { createToken, validateAccess } from './middleware';
import { getCookie, setCookie } from 'hono/cookie';

const { getUserID, getGameID } = require('./dbutils');
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
app.post('/games', validateAccess, async (c) => {
	const data = await c.req.json();

	const userId = await getUserID(c, data.username);
	if (!userId) return c.json({ error: 'User not found' }, 404);

	const createGame = await c.env.DB.prepare('INSERT INTO games (name, created_by_id) VALUES (?, ?)')
		.bind(data.name, getUserID.results[0].id)
		.run();
	if (!createGame) return c.json({ error: 'Error creating game' }, 500);

	const gameId = createGame.meta.last_row_id;
	const addPlayerResult = await c.env.DB.prepare('INSERT INTO players (user_id, game_id) VALUES (?, ?)')
		.bind(getUserID.results[0].id, gameId)
		.run();
	if (!addPlayerResult) return c.json({ error: 'Error adding player to game' }, 500);

	return c.json('Game Created');
});

// Create Player
app.post('/players', validateAccess, async (c) => {
	const data = await c.req.json();

	const createdById = await getUserID(c, data.created_by);
	if (!createdById) return c.json({ error: 'User not found' }, 404);

	const userId = await getUserID(c, data.username);
	if (!userId) return c.json({ error: 'User not found' }, 404);

	const gameId = await getGameID(c, data.game, createdById);
	if (!gameId) return c.json({ error: 'Game not found' }, 404);

	const createPlayer = await c.env.DB.prepare('INSERT INTO players (user_id, game_id) VALUES (?, ?)').bind(userId, gameId).run();
	if (!createPlayer) return c.json({ error: 'Error creating player' }, 500);

	return c.json('Player Added');
});

// Create Trade
app.post('/trades', validateAccess, async (c) => {
	console.log(c);
	return c.json('Trade Added');
});

export default app;
