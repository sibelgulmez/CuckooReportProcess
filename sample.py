import json
class sample:
    """
    A class to proccess a samaple.
    """
    def __init__(self, json_file_path):
        """
        :param json_file_path: The path of the report.json file
        """
        self.json_file_path = json_file_path
        self.json_file_content = None
        self.read_json_file()

        self.api_calls = []
        self.dlls = []
        self.dirs = []
        self.mutexes = []
        self.strings = []
        self.drops = []
        self.drop_exts = []
        self.regs = []
        self.files = []
        self.file_exts = []
        self.signatures = []

        self.fill_lists()
    def read_json_file(self):
        """
        Reads and saves the content of report.json file
        :return:
        """
        try:
            json_file = open(self.json_file_path)
            self.json_file_content = json.load(json_file)
        except Exception:
            print("Error occured while reading ", self.json_file_path)
    def fill_lists(self):
        """
        A function to fill all of the empty lists
        :return:
        """
        if (self.json_file_content != None):
            self.api_calls = self.get_api_calls()
            self.dlls = self.get_dlls()
            self.dirs = self.get_dirs()
            self.mutexes = self.get_mutexes()
            self.strings = self.get_strings()
            self.drops = self.get_drops()
            self.drop_exts = self.get_drop_exts()
            self.regs = self.get_regs()
            self.files = self.get_files()
            self.file_exts = self.get_files_ext()
            self.signatures = self.get_signatures()

            self.sort_lists()
    def get_api_calls(self):
        """
        Returns the list of api calls found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of api calls (found in a single report)
        """
        api_calls = []
        try:
            process_count = len(self.json_file_content["behavior"]["processes"]) # number of processes created by the source file
            if process_count == 0:
                return api_calls
            for process_counter in range(process_count):
                call_count = len(self.json_file_content["behavior"]["processes"][process_counter]["calls"])
                if call_count == 0:
                    continue
                for j in range(call_count):
                    api_call = self.json_file_content["behavior"]["processes"][process_counter]["calls"][j]["api"]
                    api_calls.append(api_call)
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading api calls.")
            e = Exception
        return api_calls
    def get_dlls(self):
        """
        Returns the list of dlls found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of dlls (found in a single report)
        """
        dlls = []
        try:
            for pe_import in self.json_file_content["static"]["pe_imports"]:
                if "dll" in pe_import.keys():
                    dlls.append(pe_import["dll"].lower())
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading dlls.")
            e = Exception
        return dlls
    def get_dirs(self):
        """
        Returns the list of directories found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of directories (found in a single report)
        """
        dirs = []
        # directory_enumerated
        try:
            for enumerated in self.json_file_content["behavior"]["summary"]["directory_enumerated"]:
                dir = "ENUMERATED:" + enumerated
                dirs.append(dir)
        except Exception:
            e = Exception

        # directory_created
        try:
            for created in self.json_file_content["behavior"]["summary"]["directory_created"]:
                dir = "CREATED:" + created
                dirs.append(dir)
        except Exception:
            e = Exception

        # directory_removed
        try:
            for removed in self.json_file_content["behavior"]["summary"]["directory_removed"]:
                dir = "REMOVED:" + removed
                dirs.append(dir)
        except Exception:
            e = Exception
        return dirs
    def get_mutexes(self):
        """
        Returns the list of mutual exclusions found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of mutual exclusions (found in a single report)
        """
        mutexes = []
        try:
            for mutex in self.json_file_content["behavior"]["summary"]["mutex"]:
                mutexes.append(mutex)
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return mutexes
    def get_strings(self):
        """
        Returns the list of strings found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of strings (found in a single report)
        """
        strings = []
        try:
            for string in self.json_file_content["strings"]:
                strings.append(string)
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return strings
    def get_drops(self):
        """
        Returns the list of drops found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of drops (found in a single report)
        """
        drops = []
        try:
            for dropped in self.json_file_content["dropped"]:
                filepath = dropped["filepath"]
                try:
                    directory = "\\".join(filepath.split("\\")[:-1])
                    drops.append(directory)
                except Exception:
                    e = Exception
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return drops
    def get_drop_exts(self):
        """
        Returns the list of drop extentions found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of drop extentions (found in a single report)
        """
        drop_exts = []
        try:
            for dropped in self.json_file_content["dropped"]:
                filepath = dropped["filepath"]
                try:
                    extention = filepath.split("\\")[-1].split(".")[-1]
                    if (extention.isalnum()):
                        drop_exts.append(extention)
                except Exception:
                    e = Exception
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return drop_exts
    def get_regs(self):
        """
        Returns the list of regs found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of regs (found in a single report)
        """
        regs = []
        try:
            # regkey_deleted
            try:
                for deleted in self.json_file_content["behavior"]["summary"]["regkey_deleted"]:
                    reg = "DELETED:" + deleted
                    regs.append(reg)
            except Exception:
                e = Exception

            # regkey_opened
            try:
                for opened in self.json_file_content["behavior"]["summary"]["regkey_opened"]:
                    reg = "OPENED:" + opened
                    regs.append(reg)
            except Exception:
                e = Exception

            # regkey_read
            try:
                for read in self.json_file_content["behavior"]["summary"]["regkey_read"]:
                    reg = "READ:" + read
                    regs.append(reg)
            except Exception:
                e = Exception

            # regkey_written
            try:
                for written in self.json_file_content["behavior"]["summary"]["regkey_written"]:
                    reg = "WRITTEN:" + written
                    regs.append(reg)
            except Exception:
                e = Exception

        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return regs
    def get_files(self):
        """
        Returns the list of files found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of files (found in a single report)
        """
        files = []
        # file_deleted
        try:
            for deleted in self.json_file_content["behavior"]["summary"]["file_deleted"]:
                file = "DELETED:" + deleted
                files.append(file)
        except Exception:
            e = Exception

        # file_opened
        try:
            for opened in self.json_file_content["behavior"]["summary"]["file_opened"]:
                file = "OPENED:" + "\\".join(opened.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_created
        try:
            for created in self.json_file_content["behavior"]["summary"]["file_created"]:
                file = "CREATED:" + "\\".join(created.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_recreated
        try:
            for recreated in self.json_file_content["behavior"]["summary"]["file_recreated"]:
                file = "RECREATED:" + "\\".join(recreated.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_read
        try:
            for read in self.json_file_content["behavior"]["summary"]["file_read"]:
                file = "READ:" + "\\".join(read.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_written
        try:
            for written in self.json_file_content["behavior"]["summary"]["file_written"]:
                file = "WRITTEN:" + "\\".join(written.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_exists
        try:
            for exists in self.json_file_content["behavior"]["summary"]["file_exists"]:
                file = "EXISTS:" + "\\".join(exists.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_failed
        try:
            for failed in self.json_file_content["behavior"]["summary"]["file_failed"]:
                file = "FAILED:" + "\\".join(failed.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_copied
        try:
            for copied in self.json_file_content["behavior"]["summary"]["file_copied"]:
                file = "COPIED:" + "\\".join(copied.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        # file_moved
        try:
            for moved in self.json_file_content["behavior"]["summary"]["file_moved"]:
                file = "MOVED:" + "\\".join(moved.split("\\")[:-1])
                files.append(file)
        except Exception:
            e = Exception

        return files
    def get_files_ext(self):
        """
        Returns the list of file extentions found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of file extentions (found in a single report)
        """
        file_exts = []
        # file_deleted
        try:
            for deleted in self.json_file_content["behavior"]["summary"]["file_deleted"]:
                file_ext = deleted.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("DELETED:" + file_ext)
        except Exception:
            e = Exception

        # file_opened
        try:
            for opened in self.json_file_content["behavior"]["summary"]["file_opened"]:
                file_ext = opened.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("OPENED:" + file_ext)
        except Exception:
            e = Exception

        # file_created
        try:
            for created in self.json_file_content["behavior"]["summary"]["file_created"]:
                file_ext = created.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("CREATED:" + file_ext)
        except Exception:
            e = Exception

        # file_recreated
        try:
            for recreated in self.json_file_content["behavior"]["summary"]["file_recreated"]:
                file_ext = recreated.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("RECREATED:" + file_ext)
        except Exception:
            e = Exception

        # file_read
        try:
            for read in self.json_file_content["behavior"]["summary"]["file_read"]:
                file_ext = read.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("READ:" + file_ext)
        except Exception:
            e = Exception

        # file_written
        try:
            for written in self.json_file_content["behavior"]["summary"]["file_written"]:
                file_ext = written.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("WRITTEN:" + file_ext)
        except Exception:
            e = Exception

        # file_exists
        try:
            for exists in self.json_file_content["behavior"]["summary"]["file_exists"]:
                file_ext = exists.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("EXISTS:" + file_ext)
        except Exception:
            e = Exception

        # file_failed
        try:
            for failed in self.json_file_content["behavior"]["summary"]["file_failed"]:
                file_ext = failed.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("FAILED:" + file_ext)
        except Exception:
            e = Exception

        # file_copied
        try:
            for copied in self.json_file_content["behavior"]["summary"]["file_copied"]:
                file_ext = copied.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("COPIED:" + file_ext)
        except Exception:
            e = Exception

        # file_moved
        try:
            for moved in self.json_file_content["behavior"]["summary"]["file_moved"]:
                file_ext = moved.split("\\")[-1].split(".")[-1]
                if (file_ext.isalnum()):
                    file_exts.append("MOVED:" + file_ext)
        except Exception:
            e = Exception

        return file_exts
    def get_signatures(self):
        """
        Returns the list of signatures found in the specified cuckoo report
        :param self.json_file_content: content of the cuckoo analysis report file
        :return: a list of signatures (found in a single report)
        """
        signatures = []
        for signature in self.json_file_content["signatures"]:
            try:
                signatures.append(signature["name"])
            except Exception:
                # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
                e = Exception
        return signatures
    def sort_lists(self):
        """
        A function to sort unique lists.
        :return:
        """
        self.api_calls = sorted(self.api_calls)
        self.dlls = sorted(self.dlls)
        self.dirs = sorted(self.dirs)
        self.mutexes = sorted(self.mutexes)
        self.strings = sorted(self.strings)
        self.drops = sorted(self.drops)
        self.drop_exts = sorted(self.drop_exts)
        self.regs = sorted(self.regs)
        self.files = sorted(self.files)
        self.file_exts = sorted(self.file_exts)
        self.signatures = sorted(self.signatures)
        return
