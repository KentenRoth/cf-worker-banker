import { Hono } from 'hono';
import { jwt, decode, sign, verify } from 'hono/jwt';
import { createToken, validateAccess } from './middleware';
import { getCookie, setCookie } from 'hono/cookie';

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

	setCookie(c, 'refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
	return c.json({ accessToken });
});

app.post('/token', validateAccess, async (c) => {
	const data = await c.req;
	return c.json({ message: 'refreshed' });
});

app.post('/login', async (c) => {
	const data = await c.req.json();
	const tokens = await createToken(data, c.env);
	const { accessToken, refreshToken } = tokens;

	setCookie(c, 'refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
	return c.json({ accessToken });
});

export default app;
