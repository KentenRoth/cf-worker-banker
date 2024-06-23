import { Hono } from 'hono';

type Env = {
	DB: D1Database;
};

const app = new Hono<{ Bindings: Env }>();
