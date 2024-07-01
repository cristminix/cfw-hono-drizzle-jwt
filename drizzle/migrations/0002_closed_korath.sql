CREATE TABLE `sessions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`ipaddr` text(256) NOT NULL,
	`uid` integer NOT NULL,
	`accessToken` text(50) NOT NULL,
	`timestamp` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
