export interface User {
	id: number;
	username: string;
	email: string | null;
	password: string;
	created_at: string;
}

export interface Game {
	id: number;
	name: string;
	created_by_id: number;
	created_at: string;
}

export interface Player {
	id: number;
	user_id: number;
	game_id: number;
	role: string;
	money: number;
	properties: string;
	piece: string;
	created_at: string;
}

export interface Trades {
	id: number;
	game_id: number;
	sending_player_id: number;
	receiving_player_id: number;
	items_to_send: string;
	items_to_receive: string;
	status: string;
	created_at: string;
}

export interface Requests {
	id: number;
	sending_player_id: number;
	receiving_player_id: number;
	request_type: string;
	status: string;
	created_at: string;
}

export interface Properties {
	id: number;
	color: string;
	deed: string;
	price: number;
	rent: number;
	houseCost: number;
	house1: number;
	house2: number;
	house3: number;
	house4: number;
	hotel: number;
	mortgage: number;
	isMortgaged: boolean;
	canBuyHouse: boolean;
	house: number;
	ownsAll: boolean;
}
