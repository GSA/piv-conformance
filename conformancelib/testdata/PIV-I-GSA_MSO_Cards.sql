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

INSERT INTO "TestSteps" VALUES(1,'BERTLV.1','gov.gsa.conformancelib.tests.BER_TLVTests','berTLV_Test_1',NULL);
INSERT INTO "TestSteps" VALUES(2,'BERTLV.2','gov.gsa.conformancelib.tests.BER_TLVTests','berTLV_Test_2',NULL);
INSERT INTO "TestSteps" VALUES(3,'BERTLV.3','gov.gsa.conformancelib.tests.BER_TLVTests','berTLV_Test_3',NULL);
INSERT INTO "TestSteps" VALUES(4,'BERTLV.4','gov.gsa.conformancelib.tests.BER_TLVTests','berTLV_Test_4',NULL);
INSERT INTO "TestSteps" VALUES(5,'BERTLV.5','gov.gsa.conformancelib.tests.BER_TLVTests','berTLV_Test_5',NULL);
INSERT INTO "TestSteps" VALUES(6,'73-4.1','gov.gsa.conformancelib.tests.SP800_73_4CCCTests','sp800_73_4_Test_1',NULL);
INSERT INTO "TestSteps" VALUES(7,'73-4.2','gov.gsa.conformancelib.tests.SP800_73_4CCCTests','sp800_73_4_Test_2',NULL);
INSERT INTO "TestSteps" VALUES(8,'73-4.3','gov.gsa.conformancelib.tests.SP800_73_4CCCTests','sp800_73_4_Test_3',NULL);
INSERT INTO "TestSteps" VALUES(9,'73-4.4','gov.gsa.conformancelib.tests.SP800_73_4CCCTests','sp800_73_4_Test_4',NULL);
INSERT INTO "TestSteps" VALUES(10,'73-4.5','gov.gsa.conformancelib.tests.SP800_73_4CCCTests','sp800_73_4_Test_5',NULL);
INSERT INTO "TestSteps" VALUES(11,'73-4.6','gov.gsa.conformancelib.tests.SP800_73_4CCCTests','sp800_73_4_Test_6',NULL);
INSERT INTO "TestSteps" VALUES(12,'73-4.7','gov.gsa.conformancelib.tests.SP800_73_4CCCTests','sp800_73_4_Test_7',NULL);
INSERT INTO "TestSteps" VALUES(13,'73-4.8','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_8',NULL);
INSERT INTO "TestSteps" VALUES(14,'73-4.9','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_9',NULL);
INSERT INTO "TestSteps" VALUES(15,'73-4.10','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_10',NULL);
INSERT INTO "TestSteps" VALUES(16,'73-4.11','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_11',NULL);
INSERT INTO "TestSteps" VALUES(17,'73-4.12','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_12',NULL);
INSERT INTO "TestSteps" VALUES(18,'73-4.13','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_13',NULL);
INSERT INTO "TestSteps" VALUES(19,'73-4.14','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_14',NULL);
INSERT INTO "TestSteps" VALUES(20,'73-4.15','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_15',NULL);
INSERT INTO "TestSteps" VALUES(21,'73-4.16','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_16',NULL);
INSERT INTO "TestSteps" VALUES(22,'73-4.17','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_17',NULL);
INSERT INTO "TestSteps" VALUES(23,'73-4.18','gov.gsa.conformancelib.tests.X509DataObjectTests','sp800_73_4_Test_18',NULL);
INSERT INTO "TestSteps" VALUES(24,'73-4.19','gov.gsa.conformancelib.tests.X509DataObjectTests','sp800_73_4_Test_19',NULL);
INSERT INTO "TestSteps" VALUES(25,'73-4.20','gov.gsa.conformancelib.tests.X509DataObjectTests','sp800_73_4_Test_20',NULL);
INSERT INTO "TestSteps" VALUES(26,'73-4.21','gov.gsa.conformancelib.tests.X509DataObjectTests','sp800_73_4_Test_21',NULL);
INSERT INTO "TestSteps" VALUES(27,'73-4.22','gov.gsa.conformancelib.tests.X509DataObjectTests','sp800_73_4_Test_22',NULL);
INSERT INTO "TestSteps" VALUES(28,'73-4.23','gov.gsa.conformancelib.tests.X509DataObjectTests','sp800_73_4_Test_23',NULL);
INSERT INTO "TestSteps" VALUES(29,'73-4.24','gov.gsa.conformancelib.tests.SP800_73_4FingerprintsTests','sp800_73_4_Test_24',NULL);
INSERT INTO "TestSteps" VALUES(30,'73-4.25','gov.gsa.conformancelib.tests.SP800_73_4FingerprintsTests','sp800_73_4_Test_25',NULL);
INSERT INTO "TestSteps" VALUES(31,'73-4.26','gov.gsa.conformancelib.tests.SP800_73_4FingerprintsTests','sp800_73_4_Test_26',NULL);
INSERT INTO "TestSteps" VALUES(32,'73-4.27','gov.gsa.conformancelib.tests.SP800_73_4PrintedInfoTests','sp800_73_4_Test_27',NULL);
INSERT INTO "TestSteps" VALUES(33,'73-4.28','gov.gsa.conformancelib.tests.SP800_73_4PrintedInfoTests','sp800_73_4_Test_28',NULL);
INSERT INTO "TestSteps" VALUES(34,'73-4.29','gov.gsa.conformancelib.tests.SP800_73_4PrintedInfoTests','sp800_73_4_Test_29',NULL);
INSERT INTO "TestSteps" VALUES(35,'73-4.30','gov.gsa.conformancelib.tests.SP800_73_4PrintedInfoTests','sp800_73_4_Test_30',NULL);
INSERT INTO "TestSteps" VALUES(36,'73-4.31','gov.gsa.conformancelib.tests.SP800_73_4PrintedInfoTests','sp800_73_4_Test_31',NULL);
INSERT INTO "TestSteps" VALUES(37,'73-4.32','gov.gsa.conformancelib.tests.SP800_73_4FacialImageTests','sp800_73_4_Test_32',NULL);
INSERT INTO "TestSteps" VALUES(38,'73-4.33','gov.gsa.conformancelib.tests.SP800_73_4SecurityObjectTests','sp800_73_4_Test_33',NULL);
INSERT INTO "TestSteps" VALUES(39,'73-4.34','gov.gsa.conformancelib.tests.SP800_73_4SecurityObjectTests','sp800_73_4_Test_34',NULL);
INSERT INTO "TestSteps" VALUES(40,'73-4.35','gov.gsa.conformancelib.tests.SP800_73_4SecurityObjectTests','sp800_73_4_Test_35',NULL);
INSERT INTO "TestSteps" VALUES(41,'73-4.36','gov.gsa.conformancelib.tests.SP800_73_4SecurityObjectTests','sp800_73_4_Test_36',NULL);
INSERT INTO "TestSteps" VALUES(42,'73-4.37','gov.gsa.conformancelib.tests.SP800_73_4SecurityObjectTests','sp800_73_4_Test_37',NULL);
INSERT INTO "TestSteps" VALUES(43,'73-4.38','gov.gsa.conformancelib.tests.SP800_73_4DiscoveryObjectTests','sp800_73_4_Test_38',NULL);
INSERT INTO "TestSteps" VALUES(44,'73-4.40','gov.gsa.conformancelib.tests.SP800_73_4DiscoveryObjectTests','sp800_73_4_Test_40',NULL);
INSERT INTO "TestSteps" VALUES(45,'73-4.41','gov.gsa.conformancelib.tests.SP800_73_4DiscoveryObjectTests','sp800_73_4_Test_41',NULL);
INSERT INTO "TestSteps" VALUES(46,'73-4.42','gov.gsa.conformancelib.tests.SP800_73_4DiscoveryObjectTests','sp800_73_4_Test_42',NULL);
INSERT INTO "TestSteps" VALUES(47,'73-4.43','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_43',NULL);
INSERT INTO "TestSteps" VALUES(48,'73-4.44','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_44',NULL);
INSERT INTO "TestSteps" VALUES(49,'73-4.45','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_45',NULL);
INSERT INTO "TestSteps" VALUES(50,'73-4.46','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_46',NULL);
INSERT INTO "TestSteps" VALUES(51,'73-4.47','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_47',NULL);
INSERT INTO "TestSteps" VALUES(52,'73-4.48','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_48',NULL);
INSERT INTO "TestSteps" VALUES(53,'73-4.49','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_49',NULL);
INSERT INTO "TestSteps" VALUES(54,'73-4.50','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_50',NULL);
INSERT INTO "TestSteps" VALUES(55,'73-4.51','gov.gsa.conformancelib.tests.SP800_73_4CHUIDTests','sp800_73_4_Test_51',NULL);
INSERT INTO "TestSteps" VALUES(56,'73-4.52','gov.gsa.conformancelib.tests.SP800_73_4PrintedInfoTests','sp800_73_4_Test_52',NULL);
INSERT INTO "TestSteps" VALUES(57,'73-4.53','gov.gsa.conformancelib.tests.SP800_73_4PrintedInfoTests','sp800_73_4_Test_53',NULL);
INSERT INTO "TestSteps" VALUES(58,'73-4.54','gov.gsa.conformancelib.tests.SP800_73_4SecurityObjectTests','sp800_73_4_Test_54',NULL);
INSERT INTO "TestSteps" VALUES(59,'73-4.55','gov.gsa.conformancelib.tests.SP800_73_4DiscoveryObjectTests','sp800_73_4_Test_55',NULL);
INSERT INTO "TestSteps" VALUES(60,'73-4.56','gov.gsa.conformancelib.tests.SP800_73_4CommmonObjectTests','sp800_73_4_Test_56',NULL);
INSERT INTO "TestSteps" VALUES(61,'76.1','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_1',NULL);
INSERT INTO "TestSteps" VALUES(62,'76.2','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_2',NULL);
INSERT INTO "TestSteps" VALUES(63,'76.3','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_3',NULL);
INSERT INTO "TestSteps" VALUES(64,'76.4','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_4',NULL);
INSERT INTO "TestSteps" VALUES(65,'76.5','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_5',NULL);
INSERT INTO "TestSteps" VALUES(66,'76.6','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_6',NULL);
INSERT INTO "TestSteps" VALUES(67,'76.7','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_7',NULL);
INSERT INTO "TestSteps" VALUES(68,'76.8','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_8',NULL);
INSERT INTO "TestSteps" VALUES(69,'76.9','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_9',NULL);
INSERT INTO "TestSteps" VALUES(70,'76.10','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_10',NULL);
INSERT INTO "TestSteps" VALUES(71,'76.11','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_11',NULL);
INSERT INTO "TestSteps" VALUES(72,'76.12','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_12',NULL);
INSERT INTO "TestSteps" VALUES(73,'76.13','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_13',NULL);
INSERT INTO "TestSteps" VALUES(74,'76.14','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_14',NULL);
INSERT INTO "TestSteps" VALUES(75,'76.15a','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_15a',NULL);
INSERT INTO "TestSteps" VALUES(76,'76.15b','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_15b',NULL);
INSERT INTO "TestSteps" VALUES(77,'76.16','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_16',NULL);
INSERT INTO "TestSteps" VALUES(78,'76.17','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_17',NULL);
INSERT INTO "TestSteps" VALUES(79,'76.18','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_18',NULL);
INSERT INTO "TestSteps" VALUES(80,'76.19','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_19',NULL);
INSERT INTO "TestSteps" VALUES(81,'76.20','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_20',NULL);
INSERT INTO "TestSteps" VALUES(82,'76.21','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_21',NULL);
INSERT INTO "TestSteps" VALUES(83,'76.22','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_22',NULL);
INSERT INTO "TestSteps" VALUES(84,'76.23','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_23',NULL);
INSERT INTO "TestSteps" VALUES(85,'76.24','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_24',NULL);
INSERT INTO "TestSteps" VALUES(86,'76.25','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_25',NULL);
INSERT INTO "TestSteps" VALUES(87,'76.26','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_26',NULL);
INSERT INTO "TestSteps" VALUES(88,'76.27','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_27',NULL);
INSERT INTO "TestSteps" VALUES(89,'76.28','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_28',NULL);
INSERT INTO "TestSteps" VALUES(90,'76.29','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_29',NULL);
INSERT INTO "TestSteps" VALUES(91,'76.30','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_30',NULL);
INSERT INTO "TestSteps" VALUES(92,'76.31','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_31',NULL);
INSERT INTO "TestSteps" VALUES(93,'76.32','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_32',NULL);
INSERT INTO "TestSteps" VALUES(94,'76.33','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_33',NULL);
INSERT INTO "TestSteps" VALUES(95,'76.34','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_34',NULL);
INSERT INTO "TestSteps" VALUES(96,'76.35','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_35',NULL);
INSERT INTO "TestSteps" VALUES(97,'76.36','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_36',NULL);
INSERT INTO "TestSteps" VALUES(98,'76.37','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_37',NULL);
INSERT INTO "TestSteps" VALUES(99,'76.38','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_38',NULL);
INSERT INTO "TestSteps" VALUES(100,'76.39','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_39',NULL);
INSERT INTO "TestSteps" VALUES(101,'76.40','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_40',NULL);
INSERT INTO "TestSteps" VALUES(102,'76.41','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_41',NULL);
INSERT INTO "TestSteps" VALUES(103,'76.42','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_42',NULL);
INSERT INTO "TestSteps" VALUES(104,'76.43','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_43',NULL);
INSERT INTO "TestSteps" VALUES(105,'76.44','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_44',NULL);
INSERT INTO "TestSteps" VALUES(106,'76.45','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_45',NULL);
INSERT INTO "TestSteps" VALUES(107,'76.46','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_46',NULL);
INSERT INTO "TestSteps" VALUES(108,'76.47','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_47',NULL);
INSERT INTO "TestSteps" VALUES(109,'76.48','gov.gsa.conformancelib.tests.SP800_76_Tests','sp800_76Test_48',NULL);
INSERT INTO "TestSteps" VALUES(110,'CMS.1','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_1',NULL);
INSERT INTO "TestSteps" VALUES(111,'CMS.2','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_2',NULL);
INSERT INTO "TestSteps" VALUES(112,'CMS.3','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_3',NULL);
INSERT INTO "TestSteps" VALUES(113,'CMS.4','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_4',NULL);
INSERT INTO "TestSteps" VALUES(114,'CMS.5','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_5',NULL);
INSERT INTO "TestSteps" VALUES(115,'CMS.6','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_6',NULL);
INSERT INTO "TestSteps" VALUES(116,'CMS.7','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_7',NULL);
INSERT INTO "TestSteps" VALUES(117,'CMS.8','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_8',NULL);
INSERT INTO "TestSteps" VALUES(118,'CMS.9','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_9',NULL);
INSERT INTO "TestSteps" VALUES(119,'CMS.10','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_10',NULL);
INSERT INTO "TestSteps" VALUES(120,'CMS.11','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_11',NULL);
INSERT INTO "TestSteps" VALUES(121,'CMS.12','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_12',NULL);
INSERT INTO "TestSteps" VALUES(122,'CMS.13','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_13',NULL);
INSERT INTO "TestSteps" VALUES(123,'CMS.14','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_14',NULL);
INSERT INTO "TestSteps" VALUES(124,'CMS.15','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_15',NULL);
INSERT INTO "TestSteps" VALUES(125,'CMS.17','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_17',NULL);
INSERT INTO "TestSteps" VALUES(126,'CMS.18','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_18',NULL);
INSERT INTO "TestSteps" VALUES(127,'CMS.19','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_19',NULL);
INSERT INTO "TestSteps" VALUES(128,'CMS.20','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_20',NULL);
INSERT INTO "TestSteps" VALUES(129,'CMS.21','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_21',NULL);
INSERT INTO "TestSteps" VALUES(130,'CMS.22','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_22',NULL);
INSERT INTO "TestSteps" VALUES(131,'CMS.23','gov.gsa.conformancelib.tests.CMSTests','CMS_Test_23',NULL);
INSERT INTO "TestSteps" VALUES(132,'CMS.24','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_24',NULL);
INSERT INTO "TestSteps" VALUES(133,'CMS.25','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_25',NULL);
INSERT INTO "TestSteps" VALUES(134,'CMS.26','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_26',NULL);
INSERT INTO "TestSteps" VALUES(135,'CMS.27','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_27',NULL);
INSERT INTO "TestSteps" VALUES(136,'CMS.28','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_28',NULL);
INSERT INTO "TestSteps" VALUES(137,'CMS.29','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_29',NULL);
INSERT INTO "TestSteps" VALUES(138,'CMS.30','gov.gsa.conformanceLib.tests.CMSTests','CMS_Test_30',NULL);
INSERT INTO "TestSteps" VALUES(139,'78.1','gov.gsa.conformancelib.tests.SP800_78_X509DataObjectTests','sp800_78_Test_1',NULL);
INSERT INTO "TestSteps" VALUES(140,'78.2','gov.gsa.conformancelib.tests.SP800_78_X509DataObjectTests','sp800_78_Test_2',NULL);
INSERT INTO "TestSteps" VALUES(141,'78.3','gov.gsa.conformancelib.tests.SP800_78_X509DataObjectTests','sp800_78_Test_3',NULL);
INSERT INTO "TestSteps" VALUES(142,'PKIX.1','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_1',NULL);
INSERT INTO "TestSteps" VALUES(143,'PKIX.2','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_2',NULL);
INSERT INTO "TestSteps" VALUES(144,'PKIX.3','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_3',NULL);
INSERT INTO "TestSteps" VALUES(145,'PKIX.4','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_4',NULL);
INSERT INTO "TestSteps" VALUES(146,'PKIX.5','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_5',NULL);
INSERT INTO "TestSteps" VALUES(147,'PKIX.6','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_6',NULL);
INSERT INTO "TestSteps" VALUES(148,'PKIX.7','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_7',NULL);
INSERT INTO "TestSteps" VALUES(149,'PKIX.8','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_8',NULL);
INSERT INTO "TestSteps" VALUES(150,'PKIX.9','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_9',NULL);
INSERT INTO "TestSteps" VALUES(151,'PKIX.10','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_10',NULL);
INSERT INTO "TestSteps" VALUES(152,'PKIX.11','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_11',NULL);
INSERT INTO "TestSteps" VALUES(153,'PKIX.12','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_12',NULL);
INSERT INTO "TestSteps" VALUES(154,'PKIX.13','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_13',NULL);
INSERT INTO "TestSteps" VALUES(155,'PKIX.14','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_14',NULL);
INSERT INTO "TestSteps" VALUES(156,'PKIX.15','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_15',NULL);
INSERT INTO "TestSteps" VALUES(157,'PKIX.16','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_16',NULL);
INSERT INTO "TestSteps" VALUES(158,'PKIX.17','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_17',NULL);
INSERT INTO "TestSteps" VALUES(159,'PKIX.18','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_18',NULL);
INSERT INTO "TestSteps" VALUES(160,'PKIX.19','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_19',NULL);
INSERT INTO "TestSteps" VALUES(161,'PKIX.20','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_20',NULL);
INSERT INTO "TestSteps" VALUES(162,'PKIX.21','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_21',NULL);
INSERT INTO "TestSteps" VALUES(163,'PKIX.22','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_22',NULL);
INSERT INTO "TestSteps" VALUES(164,'PKIX.23','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_23',NULL);
INSERT INTO "TestSteps" VALUES(165,'PKIX.24','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_24',NULL);
INSERT INTO "TestSteps" VALUES(166,'PKIX.25','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_25',NULL);
INSERT INTO "TestSteps" VALUES(167,'PKIX.26','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_26',NULL);
INSERT INTO "TestSteps" VALUES(168,'PKIX.27','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_27',NULL);
INSERT INTO "TestSteps" VALUES(169,'PKIX.28','gov.gsa.conformancelib.tests.PKIX_X509DataObjectTests','PKIX_Test_28',NULL);
INSERT INTO "TestSteps" VALUES(170,'PlaceholderTest.1','gov.gsa.conformancelib.tests.PlaceholderTests','PlaceholderTest_1',NULL);
INSERT INTO "TestSteps" VALUES(171,'PlaceholderTest.2','gov.gsa.conformancelib.tests.PlaceholderTests','PlaceholderTest_2',NULL);
INSERT INTO "TestSteps" VALUES(172,'PlaceholderTest.3','gov.gsa.conformancelib.tests.PlaceholderTests','PlaceholderTest_3',NULL);
INSERT INTO "TestStepParameters" VALUES(1, 21,NULL,'5',0);
INSERT INTO "TestStepParameters" VALUES(2, 99,NULL,'CARDHOLDER_FINGERPRINTS_OID:513',0);
INSERT INTO "TestStepParameters" VALUES(3, 99,NULL,'CARDHOLDER_FACIAL_IMAGE_OID:1281',1);
INSERT INTO "TestStepParameters" VALUES(4, 99,NULL,'CARDHOLDER_IRIS_IMAGES_OID:9',2);
INSERT INTO "TestStepParameters" VALUES(5, 102,NULL,'CARDHOLDER_FINGERPRINTS_OID:8',0);
INSERT INTO "TestStepParameters" VALUES(6, 102,NULL,'CARDHOLDER_FACIAL_IMAGE_OID:2',1);
INSERT INTO "TestStepParameters" VALUES(7, 102,NULL,'CARDHOLDER_IRIS_IMAGES_OID:16',2);
INSERT INTO "TestStepParameters" VALUES(8, 103,NULL,'CARDHOLDER_FINGERPRINTS_OID:128',0);
INSERT INTO "TestStepParameters" VALUES(9, 103,NULL,'CARDHOLDER_FACIAL_IMAGE_OID:32:2',1);
INSERT INTO "TestStepParameters" VALUES(10, 103,NULL,'CARDHOLDER_IRIS_IMAGES_OID:64',2);
INSERT INTO "TestStepParameters" VALUES(11, 104,NULL,'-2',0);
INSERT INTO "TestStepParameters" VALUES(12, 104,NULL,'100',1);
INSERT INTO "TestStepParameters" VALUES(13, 124,NULL,'2.16.840.1.101.3.8.7',0);
INSERT INTO "TestStepParameters" VALUES(14, 125,NULL,'1.3.6.1.1.16.4',0);
INSERT INTO "TestStepParameters" VALUES(15, 147,NULL,'X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID: 2.16.840.1.114027.200.3.10.7.13',0);
INSERT INTO "TestStepParameters" VALUES(16, 147,NULL,'X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID: 2.16.840.1.114027.200.3.10.7.6',1);
INSERT INTO "TestStepParameters" VALUES(17, 147,NULL,'X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID: 2.16.840.1.114027.200.3.10.7.4|2.16.840.1.114027.200.3.10.7.6',2);
INSERT INTO "TestStepParameters" VALUES(18, 147,NULL,'X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID: 2.16.840.1.114027.200.3.10.7.6',3);
INSERT INTO "TestStepParameters" VALUES(19, 147,NULL,'CARD_HOLDER_UNIQUE_IDENTIFIER_OID: 2.16.840.1.114027.200.3.10.7.9',4);
INSERT INTO "TestStepParameters" VALUES(20, 159,NULL,'2.16.840.1.101.3.2.1.3.19',0);
INSERT INTO "TestStepParameters" VALUES(21, 161,NULL,'CARD_HOLDER_UNIQUE_IDENTIFIER_OID:2.16.840.1.101.3.6.7',0);
INSERT INTO "TestStepParameters" VALUES(22, 161,NULL,'X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID:2.16.840.1.101.3.6.7',1);
INSERT INTO "TestStepParameters" VALUES(23, 162,NULL,'1.3.6.1.4.1.45606.3.1.22',0);
INSERT INTO "TestStepParameters" VALUES(24, 165,NULL,'2.5.29.31',0);
INSERT INTO "TestStepParameters" VALUES(25, 168,NULL,'1.3.6.1.1.16.4',0);
INSERT INTO "TestStepParameters" VALUES(26, 171,NULL,'1',0);
INSERT INTO "TestStepParameters" VALUES(27, 171,NULL,'2',1);
INSERT INTO "TestStepParameters" VALUES(28, 171,NULL,'3',2);
INSERT INTO "TestStepParameters" VALUES(29, 172,NULL,'CAT:SLEEPY',0);
INSERT INTO "TestStepParameters" VALUES(30, 172,NULL,'DOG:HUNGRY',1);
INSERT INTO "TestStepParameters" VALUES(31, 172,NULL,'ELEPHANT:SAD',2);
