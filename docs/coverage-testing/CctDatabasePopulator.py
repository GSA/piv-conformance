import argparse
import xlrd


schema = 'CREATE TABLE "TestSteps" (\n\
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,\n\
	`Description`	TEXT,\n\
        `Class`         TEXT,\n\
        `Method`        TEXT,\n\
	`NumParameters`	INTEGER\n\
);\n\
CREATE TABLE "TestsToSteps" (\n\
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,\n\
	`TestStepId`	INTEGER,\n\
	`TestId`	INTEGER,\n\
        `ExecutionOrder`         INTEGER,\n\
        `Status`        INTEGER\n\
);\n\
CREATE TABLE "TestStepParameters" (\n\
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,\n\
	`TestStepId`	INTEGER,\n\
	`TestId`	INTEGER,\n\
        `Value`         TEXT,\n\
        `ParamOrder`    TEXT\n\
);\n\
CREATE TABLE "TestCases" (\n\
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,\n\
        `TestGroup`         TEXT,\n\
	`TestCaseIdentifier`	TEXT,\n\
        `TestCaseDescription`   TEXT,\n\
        `Status`        INTEGER,\n\
        `ExpectedStatus` INTEGER,\n\
        `Enabled`   INTEGER\n\
);\n\
CREATE TABLE "TestGroups" (\n\
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,\n\
        `GroupDescription`   TEXT\n\
);\n\
CREATE TABLE "GroupsToTestCases" (\n\
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,\n\
	`TestGroupId`	INTEGER,\n\
	`TestCaseId`	INTEGER\n\
);\n\
CREATE TABLE "SystemSettings" (\n\
	`Id`	INTEGER PRIMARY KEY AUTOINCREMENT,\n\
	`ReaderName`	TEXT,\n\
	`ApplicationPIN`	TEXT,\n\
	`OutputDirectory`	TEXT,\n\
	`SettingsGroup`	TEXT,\n\
	`GPMasterKey`	TEXT\n\
);\n\
'

class test_step:
    m_id = ""
    m_description = ""
    m_class = ""
    m_method = ""
    m_omitted_numParameters = ""
    m_params = []

    def __init__(self):
        self.m_id = ""
        self.m_description = ""
        self.m_class = ""
        self.m_method = ""
        self.m_omitted_numParameters = ""
        self.m_params = []

class test_case:
    m_omitted_testGroup = ""
    m_test_case_identifier = ""
    m_test_case_description = ""
    m_omitted_status = ""
    m_expected_status = 1
    m_enabled = 1
    m_test_steps = []

    def __init__(self):
        self.m_omitted_testGroup = ""
        self.m_test_case_identifier = ""
        self.m_test_case_description = ""
        self.m_omitted_status = ""
        self.m_expected_status = 1
        self.m_enabled = 1
        self.m_test_steps = []

test_step_map = {}
test_cases = []
id_to_step = {}
id_to_case = {}


def main():
    parser = argparse.ArgumentParser(description="Generates SQL database for CCT test execution")
    parser.add_argument(
        "-i", "--input", action="store", help="Full path and filename of XLSX file containing test definifions")
    parser.add_argument(
        "-o", "--output", action="store", help="Full path and filename of sqlite database file to receive information")

    # User ID	Device UUID	IMEI	Model	Model Name	OS Version	Serial Number
    args = parser.parse_args()

    wb = xlrd.open_workbook(args.input)

    step_overview_tab = wb.sheet_by_index(1)
    ber_tlv_tab = wb.sheet_by_index(2)
    SP800_73_4_tab = wb.sheet_by_index(3)
    SP800_76_tab = wb.sheet_by_index(4)
    cms_tab = wb.sheet_by_index(5)
    SP800_78_tab = wb.sheet_by_index(6)
    pkix_tab = wb.sheet_by_index(7)
    deadbeef_tab = wb.sheet_by_index(8)

    sheets = [ber_tlv_tab, SP800_73_4_tab, SP800_76_tab, cms_tab, SP800_78_tab, pkix_tab, deadbeef_tab]

    for cur_sheet in sheets:
        for ii in range(1, cur_sheet.nrows):
            ts = test_step()
            ts.m_id = str(cur_sheet.cell_value(ii, 0)).strip()
            ts.m_class = str(cur_sheet.cell_value(ii, 1)).strip()
            ts.m_method = str(cur_sheet.cell_value(ii, 2)).strip()
            ts.m_description = str(cur_sheet.cell_value(ii, 3)).strip()
            parameters = str(cur_sheet.cell_value(ii, 4)).strip()
            if parameters:
                ts.m_params = []
                if ',' in parameters:
                    list = parameters.split(',')
                    for item in list:
                        ts.m_params.append(item.strip())
                else:
                    ts.m_params.append(parameters.strip())

            test_step_map[ts.m_id] = ts

    for ii in range(1, step_overview_tab.nrows):
        tc = test_case()
        tc.m_test_case_identifier = str(step_overview_tab.cell_value(ii, 1)).strip()
        tc.m_test_case_description = str(step_overview_tab.cell_value(ii, 2)).strip()
        test_details = str(step_overview_tab.cell_value(ii, 3)).strip()
        if test_details:
            if ',' in test_details:
                test_step_ids = test_details.split(',')
                for test_step_id in test_step_ids:
                    ts = test_step_map[test_step_id.strip()]
                    tc.m_test_steps.append(ts)
            else:
                ts = test_step_map[test_details]
                tc.m_test_steps.append(ts)

        test_cases.append(tc)

    file = open(args.output, "w")
    file.write(schema)

    id = 1
    for name in test_step_map:
        ts = test_step_map[name]
        sql = "INSERT INTO \"TestSteps\" VALUES(" + str(id) + ","
        sql = sql + "'" + ts.m_id  + "',"
        sql = sql + "'" + ts.m_class + "',"
        sql = sql + "'" + ts.m_method + "',"
        sql = sql + "NULL);\n"
        file.write(sql)
        id_to_step[ts.m_id] = id
        id = id + 1

    id = 1
    for name in test_step_map:
        ts = test_step_map[name]
        test_step_id = id_to_step[ts.m_id]
        count = 0
        for p in ts.m_params:
            sql = "INSERT INTO \"TestStepParameters\" VALUES(" + str(id) + ", "
            sql = sql + str(test_step_id)  + ","
            sql = sql + "NULL,"
            sql = sql + "'" + p + "',"
            sql = sql + str(count) + ");\n"
            file.write(sql)
            id_to_case[ts.m_id] = id
            id = id + 1
            count = count + 1

    id = 1
    for tc in test_cases:
        sql = "INSERT INTO \"TestCases\" VALUES(" + str(id) + ", NULL,"
        sql = sql + "'" + tc.m_test_case_identifier  + "',"
        sql = sql + "'" + tc.m_test_case_description + "',"
        sql = sql + "NULL, 1, 1);\n"
        file.write(sql)
        id_to_case[tc.m_test_case_identifier] = id
        id = id + 1

    id = 1
    for tc in test_cases:
        test_case_id = id_to_case[tc.m_test_case_identifier]
        count = 0
        for step in tc.m_test_steps:
            test_step_id = id_to_step[step.m_id]
            sql = "INSERT INTO \"TestsToSteps\" VALUES(" + str(id) + ", "
            sql = sql + str(test_step_id)  + ","
            sql = sql + str(test_case_id) + ","
            sql = sql + str(count) + ","
            sql = sql + "NULL);\n"
            file.write(sql)
            id_to_case[tc.m_test_case_identifier] = id
            id = id + 1
            count = count + 1

    file.close()

if __name__ == "__main__":
    main()
