CREATE TABLE users (
    id integer PRIMARY KEY,
    username varchar(255) UNIQUE,
    email varchar(255),
    password varchar,
    created_at datetime DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tokens (
    id integer PRIMARY KEY,
    token varchar,
    user_id integer,
    created_at datetime DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE games (
    id integer PRIMARY KEY,
    name varchar(255),
    winner integer,
    created_at datetime DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (winner) REFERENCES users (id)
);

CREATE TABLE players (
    id integer PRIMARY KEY,
    game_id integer,
    user_id integer,
    role varchar(255),
    money integer,
    properties varchar,
    piece varchar(255),
    created_at datetime DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (game_id) REFERENCES games (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE trades (
    id integer PRIMARY KEY,
    game_id integer,
    sending_player_id integer,
    receiving_player_id integer,
    items_to_send varchar,
    items_to_receive varchar,
    status varchar(255),
    created_at datetime DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (game_id) REFERENCES games (id),
    FOREIGN KEY (sending_player_id) REFERENCES players (id),
    FOREIGN KEY (receiving_player_id) REFERENCES players (id)
);

CREATE TABLE requests (
    id integer PRIMARY KEY,
    sending_user_id integer,
    receiving_user_id integer,
    request_type varchar(255),
    status varchar(255),
    created_at datetime DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sending_user_id) REFERENCES users (id),
    FOREIGN KEY (receiving_user_id) REFERENCES users (id)
);
