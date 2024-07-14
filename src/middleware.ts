import { MiddlewareHandler } from 'hono';
import { sign, verify } from 'hono/jwt';
import { getCookie } from 'hono/cookie';

type Env = {
	DB: any;
	REFRESH_TOKEN_SECRET: string;
	ACCESS_TOKEN_SECRET: string;
};

export const createToken = async (c: any, env: Env) => {
	let data = c;
	const { username } = data;

	const payloadAccess = { username: username, role: 'Admin', exp: Math.floor(Date.now() / 1000) + 60 * 60 };
	const payloadRefresh = { username: username, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365 };

	let accessToken = await sign(payloadAccess, env.ACCESS_TOKEN_SECRET);
	let refreshToken = await sign(payloadRefresh, env.REFRESH_TOKEN_SECRET);

	return { accessToken, refreshToken };
};

const verifyAccessToken = async (token: string, env: Env): Promise<boolean> => {
	try {
		const decoded = await verify(token, env.ACCESS_TOKEN_SECRET);
		if (!decoded || typeof decoded.exp === 'undefined') return false;
		if (decoded.exp < Date.now() / 1000) return false;
		return true;
	} catch (error) {
		return false;
	}
};

const verifyRefreshToken = async (token: string, env: Env): Promise<boolean> => {
	try {
		const decoded = await verify(token, env.REFRESH_TOKEN_SECRET);
		if (!decoded || typeof decoded.exp === 'undefined') return false;
		if (decoded.exp < Date.now() / 1000) return false;
		return true;
	} catch (error) {
		return false;
	}
};

const refreshAccessToken = async (refreshToken: string, env: Env): Promise<string | null> => {
	const decoded = await verify(refreshToken, env.REFRESH_TOKEN_SECRET);
	let payload = { username: decoded.username, role: 'Admin', exp: Math.floor(Date.now() / 1000) + 60 * 60 };
	let accessToken = sign(payload, env.ACCESS_TOKEN_SECRET);
	return accessToken;
};

export const validateAccess: MiddlewareHandler = async (c, next) => {
	const accessToken = c.req.header('Authorization')?.split(' ')[1];
	const refreshToken = await getCookie(c, 'refreshToken');
	if (!accessToken || !(await verifyAccessToken(accessToken, c.env))) {
		if (!refreshToken || !(await verifyRefreshToken(refreshToken, c.env))) {
			return c.json({ error: 'Please Login' }, 401);
		}
		let newAccessToken = await refreshAccessToken(refreshToken, c.env);
		return c.json({ accessToken: newAccessToken }, 200);
	} else {
		await next();
	}
};
