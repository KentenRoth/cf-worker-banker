import { Context } from 'hono/jsx';
import { Env } from './index';

interface User {
	id: number;
	username: string;
	email: string | null;
	password: string;
	created_at: string;
}

interface Game {
	id: number;
	name: string;
	created_by_id: number;
	created_at: string;
}

interface ExtendedContext extends Context<{ Bindings: Env }> {
	env: {
		DB: { prepare: (query: string) => any };
	};
}

export async function getUserID(c: ExtendedContext, username: string): Promise<number | null> {
	try {
		const result = (await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).run()) as D1Result<User>;
		return result.results.length > 0 ? result.results[0].id : null;
	} catch (error) {
		console.error('Error fetching user ID:', error);
		return null;
	}
}

export async function getGameID(c: ExtendedContext, name: string, createdById: number): Promise<number | null> {
	try {
		const result = (await c.env.DB.prepare('SELECT id FROM games WHERE name = ? AND created_by_id = ?')
			.bind(name, createdById)
			.run()) as D1Result<Game>;
		return result.results.length > 0 ? result.results[0].id : null;
	} catch (error) {
		console.error('Error fetching game ID:', error);
		return null;
	}
}
