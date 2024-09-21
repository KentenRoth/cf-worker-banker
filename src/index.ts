import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { createToken, validateAccess } from './middleware';
import { getCookie, setCookie } from 'hono/cookie';
import { User, Game, Player, Requests, Trades } from './Types/types';
import { verify } from 'hono/jwt';

const { getUserID, findUserID } = require('./Utils/dbutils');
const bcrypt = require('bcryptjs');

type Env = {
	DB: D1Database;
	REFRESH_TOKEN_SECRET: string;
	ACCESS_TOKEN_SECRET: string;
};

const app = new Hono<{ Bindings: Env }>();
app.use(cors({ origin: 'https://localhost:5173', credentials: true }));
type PlayerUpdateFields = Pick<Player, 'role' | 'money' | 'properties' | 'piece'>;

// Signup
app.post('/signup', async (c) => {
	const data = await c.req.json();
	const tokens = await createToken(data, c.env);
	const { accessToken, refreshToken } = tokens;

	const hashPassword = await bcrypt.hash(data.password, 8);
	const createUser = await c.env.DB.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)')
		.bind(data.username, hashPassword, data.email)
		.run();
	if (!createUser) return c.json({ error: 'Error creating user' }, 500);

	const setToken = await c.env.DB.prepare('INSERT INTO tokens (user_id, token) VALUES (?, ?)')
		.bind(createUser.meta.last_row_id, refreshToken)
		.run();
	if (!setToken) return c.json({ error: 'Error creating token' }, 500);

	setCookie(c, 'refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'None' });
	return c.json({ accessToken });
});

// Login
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

	setCookie(c, 'refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'None' });
	return c.json({ accessToken });
});

// Logout
app.post('/logout', async (c) => {
	const refreshToken = getCookie(c, 'refreshToken');
	if (!refreshToken) return c.json({ error: 'No token found' }, 404);

	const deleteToken = await c.env.DB.prepare('DELETE FROM tokens WHERE token = ?').bind(refreshToken).run();
	if (!deleteToken) return c.json({ error: 'Error deleting token' }, 500);

	setCookie(c, 'refreshToken', '', { httpOnly: true, secure: true, sameSite: 'None', maxAge: 0 });

	return c.json({ message: 'Logged out' });
});

// Logout All
app.post('/logout/all', async (c) => {
	const refreshToken = getCookie(c, 'refreshToken');
	if (!refreshToken) return c.json({ error: 'No token found' }, 404);
	let userId;
	try {
		const decoded = await verify(refreshToken, c.env.REFRESH_TOKEN_SECRET);
		userId = await findUserID(c, decoded.username);
		console.log('userId', userId);
	} catch (error) {
		return c.json({ error: 'Invalid token' }, 401);
	}

	const deleteTokens = await c.env.DB.prepare('DELETE FROM tokens WHERE user_id = ?').bind(userId).run();
	if (!deleteTokens) return c.json({ error: 'Error deleting tokens' }, 500);

	setCookie(c, 'refreshToken', '', { httpOnly: true, secure: true, sameSite: 'None', maxAge: 0 });

	return c.json({ message: 'Logged out' });
});

// Get My Info
app.get('/me', validateAccess, async (c) => {
	const userId = await getUserID(c);
	if (!userId) return c.json({ error: 'User not found' }, 404);

	console.log('userId', userId);

	const user = (await c.env.DB.prepare('SELECT username, email FROM users WHERE id = ?').bind(userId).run()) as D1Result<User>;
	if (!user) return c.json({ error: 'User not found' }, 404);

	return c.json(user.results[0]);
});

// Create Game
app.post('/games', validateAccess, async (c) => {
	const data = await c.req.json();

	const userId = await getUserID(c);
	if (!userId) return c.json({ error: 'User not found' }, 404);

	const createGame = await c.env.DB.prepare('INSERT INTO games (name, created_by_id) VALUES (?, ?)').bind(data.name, userId).run();
	if (!createGame) return c.json({ error: 'Error creating game' }, 500);

	const gameId = createGame.meta.last_row_id;
	const addPlayerResult = await c.env.DB.prepare('INSERT INTO players (user_id, game_id) VALUES (?, ?)').bind(userId, gameId).run();
	if (!addPlayerResult) return c.json({ error: 'Error adding player to game' }, 500);

	const game = await c.env.DB.prepare('SELECT * FROM games WHERE id = ?').bind(gameId).first();
	if (!game) return c.json({ error: 'Error fetching created game' }, 500);

	return c.json(game);
});

// Get Games
app.get('/games', validateAccess, async (c) => {
	const userId = await getUserID(c);

	const playerGames = (await c.env.DB.prepare('SELECT game_id FROM players WHERE user_id = ?').bind(userId).run()) as D1Result<{
		game_id: number;
	}>;
	const playerGameIds = playerGames.results.map((row) => row.game_id);

	const playerGameDetails = (await c.env.DB.prepare(
		`SELECT * FROM games WHERE id IN (${playerGameIds.join(',')})`
	).run()) as D1Result<Game>;

	return c.json(playerGameDetails.results);
});

// Get Single Game
app.get('/games/:id', validateAccess, async (c) => {
	const gameId = c.req.param('id');

	const gameResult = (await c.env.DB.prepare(
		`
        SELECT games.*, users.username AS creator_username 
        FROM games 
        JOIN users ON games.created_by_id = users.id 
        WHERE games.id = ?
    `
	)
		.bind(gameId)
		.run()) as D1Result<Game & { creator_username: string }>;

	if (gameResult.results.length === 0) return c.json({ error: 'Game not found' }, 404);

	const game = gameResult.results[0];

	const playersResult = (await c.env.DB.prepare(
		`
        SELECT players.*, users.username 
        FROM players 
        JOIN users ON players.user_id = users.id 
        WHERE players.game_id = ?
    `
	)
		.bind(gameId)
		.run()) as D1Result<Player & { username: string }>;

	const players = playersResult.results;

	return c.json({ game, players });
});

// Delete Game
app.delete('/games/:id', validateAccess, async (c) => {
	const gameId = c.req.param('id');
	const userId = await getUserID(c);

	const gameResult = await c.env.DB.prepare('SELECT created_by_id FROM games WHERE id = ?').bind(gameId).first();
	if (!gameResult) return c.json({ error: 'Game not found' }, 404);

	const createdBy = gameResult.created_by_id;

	if (userId !== createdBy) {
		return c.json({ error: 'Unauthorized' }, 403);
	}

	const deletePlayers = await c.env.DB.prepare('DELETE FROM players WHERE game_id = ?').bind(gameId).run();
	const deleteTrades = await c.env.DB.prepare('DELETE FROM trades WHERE game_id = ?').bind(gameId).run();
	const deleteGame = await c.env.DB.prepare('DELETE FROM games WHERE id = ?').bind(gameId).run();

	return c.json('Game Deleted');
});

// Create Player
app.post('/players', validateAccess, async (c) => {
	const data = await c.req.json();
	const gameId = data.game_id;

	const userId = await getUserID(c);
	if (!userId) return c.json({ error: 'User not found' }, 404);

	const existingPlayer = await c.env.DB.prepare(`SELECT 1 FROM players WHERE user_id = ? AND game_id = ?`).bind(userId, gameId).first();

	if (existingPlayer) {
		return c.json({ error: 'Player is already in the game' }, 400);
	}

	const createPlayer = await c.env.DB.prepare('INSERT INTO players (user_id, game_id) VALUES (?, ?)').bind(userId, gameId).run();
	if (!createPlayer) return c.json({ error: 'Error creating player' }, 500);

	return c.json('Player Added');
});

// Update Player
app.patch('/players', validateAccess, async (c) => {
	const data = await c.req.json();

	const userId = await getUserID(c);
	if (!userId) return c.json({ error: 'User not found' }, 404);

	const gameId = data.game;

	const allowedFields: (keyof PlayerUpdateFields)[] = ['role', 'money', 'properties', 'piece'];
	const fieldsToUpdate: string[] = [];
	const values = [];

	allowedFields.forEach((field) => {
		if (data[field] !== undefined) {
			fieldsToUpdate.push(`${field} = ?`);
			values.push(data[field]);
		}
	});

	if (fieldsToUpdate.length === 0) {
		return c.json({ error: 'No valid fields to update' }, 400);
	}

	values.push(userId, gameId);

	const updateQuery = `UPDATE players SET ${fieldsToUpdate.join(', ')} WHERE user_id = ? AND game_id = ?`;

	const updatePlayer = await c.env.DB.prepare(updateQuery)
		.bind(...values)
		.run();
	if (!updatePlayer) return c.json({ error: 'Error updating player' }, 500);

	return c.json('Player Updated');
});

// Remove Player From Game
app.delete('/players', validateAccess, async (c) => {
	const data = await c.req.json();

	const userId = await getUserID(c);
	if (!userId) return c.json({ error: 'User not found' }, 404);

	const gameId = data.game;

	const deletePlayer = await c.env.DB.prepare('DELETE FROM players WHERE user_id = ? AND game_id = ?').bind(userId, gameId).run();
	if (!deletePlayer) return c.json({ error: 'Error deleting player' }, 500);

	return c.json('Player Deleted');
});

// Friends/Game Requests
app.post('/requests', validateAccess, async (c) => {
	const data = await c.req.json();

	const sendingPlayerId = await getUserID(c);
	if (!sendingPlayerId) return c.json({ error: 'Sending player not found' }, 404);

	const receivingPlayerId = await findUserID(c, data.receiving_player);
	if (!receivingPlayerId) return c.json({ error: 'Receiving player not found' }, 404);

	const createRequest = await c.env.DB.prepare('INSERT INTO requests (sending_user_id, receiving_user_id, request_type) VALUES (?, ?, ?)')
		.bind(sendingPlayerId, receivingPlayerId, data.request_type)
		.run();
	if (!createRequest) return c.json({ error: 'Error creating request' }, 500);

	return c.json(createRequest);
});

// Get Friends/Game Requests
app.get('/requests', validateAccess, async (c) => {
	const user = await getUserID(c);

	const requests = (await c.env.DB.prepare('SELECT * FROM requests WHERE sending_user_id = ? OR receiving_user_id = ?')
		.bind(user, user)
		.run()) as D1Result<Requests>;
	if (!requests) return c.json({ error: 'Error fetching requests' }, 500);

	return c.json(requests.results);
});

// Update Friends/Game Requests
app.patch('/requests', validateAccess, async (c) => {
	const data = await c.req.json();
	const user = await getUserID(c);

	const request = await c.env.DB.prepare('SELECT sending_user_id, receiving_user_id FROM requests WHERE id = ?').bind(data.id).first();
	if (!request) return c.json({ error: 'Request not found' }, 404);

	if (request.sending_user_id !== user && request.receiving_user_id !== user) {
		return c.json({ error: 'Unauthorized' }, 403);
	}

	const updateRequest = await c.env.DB.prepare('UPDATE requests SET status = ? WHERE id = ?').bind(data.status, data.id).run();
	if (!updateRequest) return c.json({ error: 'Error updating request' }, 500);

	return c.json('Request Updated');
});

// Create Trade
app.post('/trades', validateAccess, async (c) => {
	const data = await c.req.json();
	const sendingPlayerId = await getUserID(c);

	const recievingPlayerId = await findUserID(c, data.recieving_player);
	if (!recievingPlayerId) return c.json({ error: 'Receiving player not found' }, 404);

	const itemsToSend = JSON.stringify(data.items_to_send);
	const itemsToReceive = JSON.stringify(data.items_to_receive);

	const createTrade = await c.env.DB.prepare(
		'INSERT INTO trades (game_id, sending_player_id, receiving_player_id, items_to_send, items_to_receive) VALUES (?, ?, ?, ?, ?)'
	)
		.bind(data.game_id, sendingPlayerId, recievingPlayerId, itemsToSend, itemsToReceive)
		.run();

	if (!createTrade) return c.json({ error: 'Error creating trade' }, 500);

	return c.json('Trade Created');
});

// Get Trades
app.get('/trades', validateAccess, async (c) => {
	const user = await getUserID(c);
	const data = await c.req.json();

	const trades = (await c.env.DB.prepare(
		`
		SELECT trades.*, users.username AS sending_player_username, receiving_players.username AS receiving_player_username 
		FROM trades 
		JOIN users ON trades.sending_player_id = users.id 
		JOIN users AS receiving_players ON trades.receiving_player_id = receiving_players.id 
		WHERE (trades.sending_player_id = ? OR trades.receiving_player_id = ?) AND trades.game_id = ?
		`
	)
		.bind(user, user, data.game_id)
		.all()) as D1Result<Trades & { sending_player_username: string; receiving_player_username: string }>;
	console.log(trades);

	return c.json(trades.results);
});

// Update Trade
app.patch('/trades', validateAccess, async (c) => {
	const data = await c.req.json();
	const userId = await getUserID(c);

	const trade = await c.env.DB.prepare(`SELECT sending_player_id, receiving_player_id FROM trades WHERE game_id = ? AND id = ?`)
		.bind(data.game_id, data.trade_id)
		.first();

	console.log(trade);
	if (!trade) return c.json({ error: 'Trade not found' }, 404);

	if (trade.sending_player_id !== userId && trade.receiving_player_id !== userId) {
		return c.json({ error: 'User not authorized to update this trade' }, 403);
	}

	const updateTrade = await c.env.DB.prepare(`UPDATE trades SET status = ? WHERE game_id = ? AND id = ?`)
		.bind(data.status, data.game_id, data.trade_id)
		.run();

	if (!updateTrade) return c.json({ error: 'Error updating trade' }, 500);

	return c.json('Trade Updated');
});

export default app;
