import { Context } from 'hono/jsx';
import { decode } from 'hono/jwt';
import { User } from '../Types/types';

interface ExtendedContext extends Context<{ Bindings: Env }> {
	env: {
		DB: { prepare: (query: string) => any };
		ACCESS_TOKEN_SECRET: string;
	};
	req: { header: (key: string) => string | null };
}

export async function findUserID(c: ExtendedContext, username: string): Promise<number | null> {
	try {
		const result = (await c.env.DB.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').bind(username).run()) as D1Result<User>;
		return result.results.length > 0 ? result.results[0].id : null;
	} catch (error) {
		console.error('Error fetching user ID:', error);
		return null;
	}
}

export async function getUserID(c: ExtendedContext): Promise<number | null> {
	const authHeader = c.req.header('Authorization')?.split(' ')[1];

	if (!authHeader) return null;
	const decodedToken = await decode(authHeader);
	let username = decodedToken.payload.username;

	try {
		const result = (await c.env.DB.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').bind(username).run()) as D1Result<User>;
		return result.results.length > 0 ? result.results[0].id : null;
	} catch (error) {
		console.error('Error fetching user ID:', error);
		return null;
	}
}
