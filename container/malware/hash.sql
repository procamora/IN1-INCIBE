BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "hash" (
	"id"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	"file"	TEXT,
	"md5"	TEXT UNIQUE,
	"json"	TEXT,
	"url"	TEXT,
	"state" INTEGER
);


CREATE TABLE IF NOT EXISTS "states" (
	"id"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	"state" TEXT,
	"description" TEXT
);

INSERT INTO states(id, state, description) VALUES (1, "Ok", "Scan finished, information embedded");
INSERT INTO states(id, state, description) VALUES (2, "Not Exists", "The requested resource is not among the finished, queued or pending scans");
INSERT INTO states(id, state, description) VALUES (3, "Analyzing", "Scan request successfully queued, come back later for the report");
INSERT INTO states(id, state, description) VALUES (4, "Error", "Invalid resource, check what you are submitting");

COMMIT;
