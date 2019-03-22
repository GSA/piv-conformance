CREATE TABLE IF NOT EXISTS "TestSteps" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`Description`	TEXT,
        `Class`         TEXT,
        `Method`        TEXT,
	`NumParameters`	INTEGER
);

CREATE TABLE IF NOT EXISTS "TestsToSteps" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestStepId`	INTEGER,
	`TestId`	INTEGER,
        `ExecutionOrder`         INTEGER,
        `Status`        INTEGER
);

CREATE TABLE IF NOT EXISTS "TestStepParameters" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestStepId`	INTEGER,
	`TestId`	INTEGER,
        `Value`         TEXT
);

CREATE TABLE IF NOT EXISTS "TestCases" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
        `TestGroup`         TEXT,
	`TestCaseIdentifier`	TEXT,
        `TestCaseDescription`   TEXT,
        `Status`        INTEGER,
        `ExpectedStatus` INTEGER
);

CREATE TABLE IF NOT EXISTS "TestGroups" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
        `GroupDescription`   TEXT
);

CREATE TABLE IF NOT EXISTS "GroupsToTestCases" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestGroupId`	INTEGER,
	`TestCaseId`	INTEGER
);

-- this isn't really going to be used by the look of things. probably should
-- be eliminated
CREATE TABLE IF NOT EXISTS "SystemSettings" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`ReaderName`	TEXT,
	`ApplicationPIN`	TEXT,
	`OutputDirectory`	TEXT,
	`SettingsGroup`	TEXT,
	`GPMasterKey`	TEXT
);

