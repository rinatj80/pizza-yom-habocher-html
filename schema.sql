CREATE TABLE `pizza_orders` (
	`id` text PRIMARY KEY NOT NULL,
	`batch_id` text NOT NULL,
	`payload` text NOT NULL,
	`created_at` text NOT NULL
);

CREATE TABLE admin_login_attempts (identity TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_start INTEGER NOT NULL);
