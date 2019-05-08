-- TestSteps are what we've been referring to as atoms
CREATE TABLE IF NOT EXISTS "TestSteps" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`Description`	TEXT, -- column 2 on each tab
        `Class`         TEXT, -- fully qualified class name
        `Method`        TEXT, -- method to invoke for the atom
	`NumParameters`	INTEGER -- parameter count. not really necessary but was briefly helpful, so it's still here
);

-- Map test cases to their atoms
CREATE TABLE IF NOT EXISTS "TestsToSteps" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestStepId`	INTEGER, --Foreign key TestSteps.Id
	`TestId`	INTEGER, --Foreign key TestCases.Id
        `ExecutionOrder`         INTEGER, --Sequence of atoms for a test case
        `Status`        INTEGER -- runners can populate with status info to see which step failed
);

-- used to pass parameters to atoms
CREATE TABLE IF NOT EXISTS "TestStepParameters" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestStepId`	INTEGER, --TestSteps.Id
	`TestId`	INTEGER, --TestCases.Id
        `Value`         TEXT, --Parameter Value
        `ParamOrder`    TEXT --Parameter order... idea here was one row for each pattern to be passed into a particular invocation of an atom.
        --If we settle on a string of key=value for the Value field, this could be OBE
);

-- TestCases is the primary driver of the test runner
CREATE TABLE IF NOT EXISTS "TestCases" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
        `TestGroup`         TEXT, -- can be filled in to allow selective execution by the runner. not in spreadsheet
	`TestCaseIdentifier`	TEXT, -- section column on step overview tab
        `TestCaseDescription`   TEXT, -- description column on step overview tab
        `TestCaseContainer` TEXT, -- ID of the container the test case applies to, if necessary
        `Status`        INTEGER, -- to be populated by runner
        `ExpectedStatus` INTEGER, -- everything on the spreadsheet should get 1 here - primarily present to give runners a way to mark tests that should fail
        `Enabled`   INTEGER -- allows the runner to enable/disable test cases. default to 1
);

-- Allow runners to create test groups. not in spreadsheet
CREATE TABLE IF NOT EXISTS "TestGroups" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
        `GroupDescription`   TEXT
);

-- Allow runners to create test groups. not in spreadsheet
CREATE TABLE IF NOT EXISTS "GroupsToTestCases" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestGroupId`	INTEGER, --TestGroups.Id
	`TestCaseId`	INTEGER --TestCases.Id
);

-- this isn't really going to be used by the look of things. probably should
-- be eliminated, but it's harmless and has been intermittently useful in dev.
CREATE TABLE IF NOT EXISTS "SystemSettings" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`ReaderName`	TEXT,
	`ApplicationPIN`	TEXT,
	`OutputDirectory`	TEXT,
	`SettingsGroup`	TEXT,
	`GPMasterKey`	TEXT
);

