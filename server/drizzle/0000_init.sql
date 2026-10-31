CREATE TABLE `users` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`password` text NOT NULL,
	`public_key` text,
	`encrypted_private_key` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_name_unique` ON `users` (`name`);--> statement-breakpoint
CREATE TABLE `rooms` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`description` text DEFAULT '' NOT NULL,
	`force_membership` integer DEFAULT 0 NOT NULL,
	`is_private` integer DEFAULT 0 NOT NULL,
	`is_direct` integer DEFAULT 0 NOT NULL,
	`key_version` integer DEFAULT 1 NOT NULL,
	`needs_rekey` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `rooms_name_unique` ON `rooms` (`name`);--> statement-breakpoint
CREATE TABLE `room_member` (
	`room_id` integer NOT NULL,
	`user_name` text NOT NULL,
	PRIMARY KEY(`room_id`, `user_name`),
	FOREIGN KEY (`room_id`) REFERENCES `rooms`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`user_name`) REFERENCES `users`(`name`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `messages` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`room_id` integer NOT NULL,
	`user_name` text NOT NULL,
	`content` text,
	`iv` text,
	`auth_tag` text,
	`ciphertext` text,
	`keys` text,
	`key_version` integer,
	`timestamp` integer NOT NULL,
	FOREIGN KEY (`room_id`) REFERENCES `rooms`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`user_name`) REFERENCES `users`(`name`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `room_keys` (
	`room_id` integer NOT NULL,
	`user_name` text NOT NULL,
	`version` integer DEFAULT 1 NOT NULL,
	`encrypted_key` text NOT NULL,
	PRIMARY KEY(`room_id`, `user_name`, `version`),
	FOREIGN KEY (`room_id`) REFERENCES `rooms`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`user_name`) REFERENCES `users`(`name`) ON UPDATE no action ON DELETE no action
);
