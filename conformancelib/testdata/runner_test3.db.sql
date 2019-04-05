PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "TestSteps" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`Description`	TEXT,
        `Class`         TEXT,
        `Method`        TEXT,
	`NumParameters`	INTEGER
);
INSERT INTO TestSteps VALUES(1,'BERTLV.1','gov.gsa.conformanceLib.tests.BER_TLVTests','berTLV_Test_1',NULL);
INSERT INTO TestSteps VALUES(2,'BERTLV.2','gov.gsa.conformanceLib.tests.BER_TLVTests','berTLV_Test_2',NULL);
INSERT INTO TestSteps VALUES(3,'BERTLV.3','gov.gsa.conformanceLib.tests.BER_TLVTests','berTLV_Test_3',NULL);
INSERT INTO TestSteps VALUES(4,'BERTLV.4','gov.gsa.conformanceLib.tests.BER_TLVTests','berTLV_Test_4',NULL);
INSERT INTO TestSteps VALUES(5,'PKIX.1','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_1',NULL);
INSERT INTO TestSteps VALUES(6,'PKIX.2','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_2',NULL);
INSERT INTO TestSteps VALUES(7,'PKIX.3','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_3',NULL);
INSERT INTO TestSteps VALUES(8,'PKIX.4','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_4',NULL);
INSERT INTO TestSteps VALUES(9,'PKIX.5','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_5',NULL);
INSERT INTO TestSteps VALUES(10,'PKIX.6','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_6',1);
CREATE TABLE IF NOT EXISTS "TestsToSteps" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestStepId`	INTEGER,
	`TestId`	INTEGER,
        `ExecutionOrder`         INTEGER,
        `Status`        INTEGER
);
INSERT INTO TestsToSteps VALUES(1,1,183,1,NULL);
INSERT INTO TestsToSteps VALUES(2,2,183,2,NULL);
INSERT INTO TestsToSteps VALUES(3,5,184,1,NULL);
INSERT INTO TestsToSteps VALUES(5,6,184,2,NULL);
INSERT INTO TestsToSteps VALUES(6,7,184,3,NULL);
INSERT INTO TestsToSteps VALUES(7,8,184,4,NULL);
INSERT INTO TestsToSteps VALUES(8,9,184,5,NULL);
INSERT INTO TestsToSteps VALUES(9,10,184,6,NULL);
CREATE TABLE IF NOT EXISTS "TestStepParameters" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestStepId`	INTEGER,
	`TestId`	INTEGER,
        `Value`         TEXT,
        `ParamOrder`    TEXT
);
INSERT INTO TestStepParameters VALUES(1,10,184,replace('2.16.840.1.101.3.2.1.48.11\n','\n',char(10)),NULL);
CREATE TABLE IF NOT EXISTS "TestCases" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
        `TestGroup`         TEXT,
	`TestCaseIdentifier`	TEXT,
        `TestCaseDescription`   TEXT,
        `Status`        INTEGER,
        `ExpectedStatus` INTEGER,
        `Enabled`   INTEGER
);
INSERT INTO TestCases VALUES(183,NULL,'8.1','Confirm that CCC of PIV card Applet conforms to SP800-73 Appendix A',NULL,1,NULL);
INSERT INTO TestCases VALUES(184,NULL,'11.1.2',replace('Verify data integrity of PIV auth certificate\n','\n',char(10)),NULL,1,NULL);
CREATE TABLE IF NOT EXISTS "TestGroups" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
        `GroupDescription`   TEXT
);
CREATE TABLE IF NOT EXISTS "GroupsToTestCases" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`TestGroupId`	INTEGER,
	`TestCaseId`	INTEGER
);
CREATE TABLE IF NOT EXISTS "SystemSettings" (
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`ReaderName`	TEXT,
	`ApplicationPIN`	TEXT,
	`OutputDirectory`	TEXT,
	`SettingsGroup`	TEXT,
	`GPMasterKey`	TEXT
);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('TestsToSteps',9);
INSERT INTO sqlite_sequence VALUES('TestSteps',10);
INSERT INTO sqlite_sequence VALUES('TestStepParameters',1);
INSERT INTO sqlite_sequence VALUES('TestCases',184);
COMMIT;
