import json, shutil, os

class dataset:
    """
    A class to proccess the whole dataset.
    """
    def __init__(self, cuckoo_directory, get_json_paths_only = False, sample_count = 0, min_count = 5 ):
        """
        This class defines the list of report.json files' paths. To do that, the cuckoo analysis folders are getting "refreshed" first. Refreshing a cucckoo analysis folder deletesed itself except the report.json file. Only that file is kept and it is also renamed with the source executable file's name
        :param cuckoo_directory: The directory of cuckoo analysis folder which includes a number of analysis folders.
        :param get_json_paths_only: If True, this means that the folders are already refreshed and report.json files are moved. In that case, it is enough to return the list of these report.json files.
        :param sample_count: Number of files to fetch. If 0, all of the files are fetched, Default = 0
        :param min_count: minimum number of features to be appeared, so that they are saved in the 'unique' element lists. Default = 5
        """
        self.cuckoo_directory = cuckoo_directory
        self.sample_count = sample_count
        self.min_count = min_count
        self.analysis_folders = self.get_analysis_folders()

        if get_json_paths_only:
            self.json_paths = self.get_json_paths()
        else:
            self.json_paths =  self.refresh_directories()

        self.unique_api_calls = []
        self.unique_dlls = []
        self.unique_dirs = []
        self.unique_mutexes = []
        self.unique_strings = []
        self.unique_drops = []
        self.unique_drop_exts = []
        self.unique_regs = []
        self.unique_files = []
        self.unique_file_exts = []
        self.unique_signatures = []
        self.unique_signature_references = []
        self.unique_drop_types = []

        self.create_unique_lists()

    def get_analysis_folders(self):
        """
        A function to list all of the analysis folders found in the main cuckoo directory.
        :return: List all analysis folders found in the main cuckoo directory
        """
        folder_list = []
        folder_names = os.listdir(self.cuckoo_directory)
        for folder_name in folder_names:
            folder_list.append(os.path.join(self.cuckoo_directory, folder_name))
        if self.sample_count == 0:
            return folder_list
        return folder_list[:self.sample_count]
    def get_json_paths(self):
        """
        A function to list all of the .json files in the specified directory
        :return: List all .json files in the specified directory
        """
        print("Collecting json files.")
        folder_list = []
        folder_names = os.listdir(self.cuckoo_directory)
        for folder_name in folder_names:
            if folder_name.endswith(".json"):
                folder_list.append(os.path.join(self.cuckoo_directory, folder_name))
        if self.sample_count == 0:
            return folder_list
        return folder_list[:self.sample_count]
    def refresh_directories(self):
        """
        A function to refresh the analysis folders. This function deletes the analysis folders except "report.json" file.
        It also renames this file with the source executable's name, so that the multiple report.json files don't get mixed.
        :return: The list of the report.json paths (after the move and rename operation)
        """
        json_paths = []
        for analysis_folder in self.analysis_folders:
            file_name = self.get_source_file_name(analysis_folder)
            report_json_path = self.get_report_json_path(analysis_folder)
            if (file_name != "" and report_json_path != ""):
                new_report_json_path = self.move_json_file(report_json_path, file_name)
                json_paths.append(new_report_json_path)
                self.delete_folder(analysis_folder)
            else:
                print("Error occured with the analysis folder: ", analysis_folder)
        print("Refreshed folders.")
        return json_paths
    def get_source_file_name (self, analysis_folder_path):
        """
        A function to find the source executable file's name by using the task.json file in the analysis folder
        :param analysis_folder_path: path of the cuckoo analysis folder
        :return: name of the source executable file
        """
        task_json_path = self.get_task_json_path(analysis_folder_path)
        if (task_json_path == ""):
            return ""
        json_file = open(task_json_path)
        json_content = json.load(json_file)
        file_name = json_content["target"].split("/")[-1]
        if (file_name.find(".") > 0): # deleting the extention if any
            return (file_name.split(".")[0])
        return file_name
    def get_report_json_path(self, analysis_folder_path):
        """
        A function to find the path of report.json path in the specified cuckoo analysis folder
        :param analysis_folder_path: path of the cuckoo analysis folder
        :return: path of the report.json path
        """
        report_json_path = analysis_folder_path + "/reports/report.json"
        exists = os.path.exists(report_json_path)
        if exists:
            return (analysis_folder_path + "/reports/report.json")
        return ""
    def get_task_json_path(self, analysis_folder_path):
        """
        A function to find the path of task.json path in the specified cuckoo analysis folder
        :param analysis_folder_path: path of the cuckoo analysis folder
        :return: path of the task.json path
        """
        task_json_path = analysis_folder_path + "/task.json"
        exists = os.path.exists(task_json_path)
        if exists:
            return (analysis_folder_path + "/task.json")
        return ""
    def move_json_file(self, report_json_path, file_name):
        """
        A function to move report.json file and rename it
        :param report_json_path: path of the report.json file
        :param file_name: new name of the report.json file
        :return:
        """
        from_dir = report_json_path
        previous = "/".join(from_dir.split("/")[-3:])
        new = file_name + ".json"
        to_dir = report_json_path.replace(previous, new)
        shutil.move(from_dir, to_dir)
        return to_dir
    def delete_folder(self, analysis_folder_path):
        """
        A function to delete a cuckoo analysis folder
        :param analysis_folder_path: path of the cuckoo analysis folder
        :return:
        """
        shutil.rmtree(analysis_folder_path)
        return
    def dict_filler(self, _dict, _list):
        """
        A function to fill a dictionary with a list. Dictionary's value is the number of occurances of that key.
        :param _dict: dictionary to be filled
        :param _list: source list
        :return: updated dictionary
        """
        # deleting reoccurances
        _list = list(set(_list))
        for item in _list:
            if item not in _dict.keys():
                _dict[item] = 1
            else:
                _dict[item] += 1
        return _dict
    def dict_to_list(self, _dict):
        """
        A function to create a list from a dictionary by using the self.min_count. If a key's value is larger than or equal to min_count, then it should be in the list.
        :param _dict: source dictionary
        :return: list of some of the keys of the source dictionary
        """
        _list = []
        for key in _dict.keys():
            if _dict[key] >= self.min_count:
                _list.append(key)
        return _list
    def create_unique_lists(self):
        print("Generating feature sets...")

        # defining empty dictionaries
        unique_api_calls_dict = dict()
        unique_dlls_dict = dict()
        unique_dirs_dict = dict()
        unique_mutexes_dict = dict()
        unique_strings_dict = dict()
        unique_drops_dict = dict()
        unique_drop_exts_dict = dict()
        unique_regs_dict = dict()
        unique_files_dict = dict()
        unique_file_exts_dict = dict()
        unique_signatures_dict = dict()
        unique_signature_references_dict = dict()
        unique_drop_types_dict = dict()

        # filling dictionaries by using all of the files
        for report_json_path in self.json_paths:
            try:
                # read file
                json_file = open(report_json_path)
                json_file_content = json.load(json_file)

                # api calls
                api_calls = self.get_api_calls(json_file_content)
                unique_api_calls_dict = self.dict_filler(unique_api_calls_dict, api_calls)

                # dlls
                dlls = self.get_dlls(json_file_content)
                unique_dlls_dict = self.dict_filler(unique_dlls_dict, dlls)

                # enumdirs
                dirs = self.get_dirs(json_file_content)
                unique_dirs_dict = self.dict_filler(unique_dirs_dict, dirs)

                # mutexes
                mutexes = self.get_mutexes(json_file_content)
                unique_mutexes_dict = self.dict_filler(unique_mutexes_dict, mutexes)

                # strings
                strings = self.get_strings(json_file_content)
                unique_strings_dict = self.dict_filler(unique_strings_dict, strings)

                # drops
                drops = self.get_drops(json_file_content)
                unique_drops_dict = self.dict_filler(unique_drops_dict, drops)

                # drop_exts
                drop_exts = self.get_drop_exts(json_file_content)
                unique_drop_exts_dict = self.dict_filler(unique_drop_exts_dict, drop_exts)

                # drop_types
                drop_types = self.get_drop_types(json_file_content)
                unique_drop_types_dict = self.dict_filler(unique_drop_types_dict, drop_types)

                # regs
                regs = self.get_regs(json_file_content)
                unique_regs_dict = self.dict_filler(unique_regs_dict, regs)

                # files
                files = self.get_files(json_file_content)
                unique_files_dict = self.dict_filler(unique_files_dict, files)

                # files_ext
                file_exts = self.get_files_ext(json_file_content)
                unique_file_exts_dict = self.dict_filler(unique_file_exts_dict, file_exts)

                # signatures
                signatures = self.get_signatures(json_file_content)
                unique_signatures_dict = self.dict_filler(unique_signatures_dict, signatures)

                # signature_references
                signature_references = self.get_signature_references(json_file_content)
                unique_signature_references_dict = self.dict_filler(unique_signature_references_dict, signature_references)

            except Exception:
                e = Exception

        # filling lists, by using dictionaries
        self.unique_api_calls = self.dict_to_list(unique_api_calls_dict)
        self.unique_dlls = self.dict_to_list(unique_dlls_dict)
        self.unique_dirs = self.dict_to_list(unique_dirs_dict)
        self.unique_mutexes = self.dict_to_list(unique_mutexes_dict)
        self.unique_strings = self.dict_to_list(unique_strings_dict)
        self.unique_drops = self.dict_to_list(unique_drops_dict)
        self.unique_drop_exts = self.dict_to_list(unique_drop_exts_dict)
        self.unique_regs = self.dict_to_list(unique_regs_dict)
        self.unique_files = self.dict_to_list(unique_files_dict)
        self.unique_file_exts = self.dict_to_list(unique_file_exts_dict)
        self.unique_signatures = self.dict_to_list(unique_signatures_dict)
        self.unique_signature_references = self.dict_to_list(unique_signature_references_dict)
        self.unique_drop_types = self.dict_to_list(unique_drop_types_dict)

        # sorting lists
        self.sort_lists()

        return
    def get_api_calls(self, json_file_content):
        """
        Returns the list of api calls found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of api calls (found in a single report)
        """
        api_calls = []
        try:
            process_count = len(json_file_content["behavior"]["processes"]) # number of processes created by the source file
            if process_count == 0:
                return api_calls
            for process_counter in range(process_count):
                call_count = len(json_file_content["behavior"]["processes"][process_counter]["calls"])
                if call_count == 0:
                    continue
                for j in range(call_count):
                    api_call = json_file_content["behavior"]["processes"][process_counter]["calls"][j]["api"]
                    api_calls.append(api_call)
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading api calls.")
            e = Exception
        return api_calls
    def get_dlls(self, json_file_content):
        """
        Returns the list of dlls found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of dlls (found in a single report)
        """
        dlls = []
        try:
            for pe_import in json_file_content["static"]["pe_imports"]:
                if "dll" in pe_import.keys():
                    dlls.append(pe_import["dll"].lower())
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading dlls.")
            e = Exception
        return dlls
    def get_dirs(self, json_file_content):
        """
        Returns the list of directories found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of directories (found in a single report)
        """
        dirs = []
        # directory_enumerated
        try:
            for enumerated in json_file_content["behavior"]["summary"]["directory_enumerated"]:
                dir = "ENUMERATED:" + enumerated
                dirs.append(dir)
        except Exception:
            e = Exception

        # directory_created
        try:
            for created in json_file_content["behavior"]["summary"]["directory_created"]:
                dir = "CREATED:" + created
                dirs.append(dir)
        except Exception:
            e = Exception

        # directory_removed
        try:
            for removed in json_file_content["behavior"]["summary"]["directory_removed"]:
                dir = "REMOVED:" + removed
                dirs.append(dir)
        except Exception:
            e = Exception
        return dirs
    def get_mutexes(self, json_file_content):
        """
        Returns the list of mutual exclusions found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of mutual exclusions (found in a single report)
        """
        mutexes = []
        try:
            for mutex in json_file_content["behavior"]["summary"]["mutex"]:
                mutexes.append(mutex)
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return mutexes
    def get_strings(self, json_file_content):
        """
        Returns the list of strings found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of strings (found in a single report)
        """
        strings = []
        try:
            for string in json_file_content["strings"]:
                strings.append(string)
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return strings
    def get_drops(self, json_file_content):
        """
        Returns the list of drops found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of drops (found in a single report)
        """
        drops = []
        try:
            for dropped in json_file_content["dropped"]:
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
    def get_drop_exts(self, json_file_content):
        """
        Returns the list of drop extentions found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of drop extentions (found in a single report)
        """
        drop_exts = []
        try:
            for dropped in json_file_content["dropped"]:
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
    def get_drop_types(self, json_file_content):
        """
        Returns the list of drop types found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of drop types (found in a single report)
        """
        drop_types = []
        try:
            for dropped in json_file_content["dropped"]:
                drop_type = dropped["filepath"]
                drop_types.append(drop_type)
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading mutual exclusions.")
            e = Exception
        return drop_types
    def get_regs(self, json_file_content):
        """
        Returns the list of regs found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of regs (found in a single report)
        """
        regs = []
        # regkey_deleted
        try:
            for deleted in json_file_content["behavior"]["summary"]["regkey_deleted"]:
                reg = "DELETED:" + deleted
                regs.append(reg)
        except Exception:
            e = Exception

        # regkey_opened
        try:
            for opened in json_file_content["behavior"]["summary"]["regkey_opened"]:
                reg = "OPENED:" + opened
                regs.append(reg)
        except Exception:
            e = Exception

        # regkey_read
        try:
            for read in json_file_content["behavior"]["summary"]["regkey_read"]:
                reg = "READ:" + read
                regs.append(reg)
        except Exception:
            e = Exception

        # regkey_written
        try:
            for written in json_file_content["behavior"]["summary"]["regkey_written"]:
                reg = "WRITTEN:" + written
                regs.append(reg)
        except Exception:
            e = Exception
        return regs
    def get_files(self, json_file_content):
        """
        Returns the list of files found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of files (found in a single report)
        """
        files = []

        try:
            for key in json_file_content["behavior"]["summary"].keys():
                if key.startswith("file_"):
                    operation_type = key.replace("file_", "").upper() + ":"
                    for processed_file in json_file_content["behavior"]["summary"][key]:
                        file = ("\\").join(processed_file.split("\\")[:-1])
                        files.append(operation_type + file)
        except Exception:
            e = Exception
        return files
    def get_files_ext(self, json_file_content):
        """
        Returns the list of file extentions found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of file extentions (found in a single report)
        """
        file_exts = []

        try:
            for key in json_file_content["behavior"]["summary"].keys():
                if key.startswith("file_"):
                    operation_type = key.replace("file_", "").upper() + ":"
                    for processed_file in json_file_content["behavior"]["summary"][key]:
                        file_ext = processed_file.split("\\")[-1].split(".")[-1]
                        if (file_ext.isalnum()):
                            file_exts.append(operation_type + file_ext)
        except Exception:
            e = Exception
        return file_exts
    def get_signatures(self, json_file_content):
        """
        Returns the list of signatures found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of signatures (found in a single report)
        """
        signatures = []
        try:
            for signature in json_file_content["signatures"]:
                try:
                    signatures.append(signature["name"])
                except Exception:
                    # print("Exception occured in the file", report_json_path, "while reading signatures.")
                    e = Exception
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading signatures.")
            e = Exception
        return signatures
    def get_signature_references(self, json_file_content):
        """
        Returns the list of signature references found in the specified cuckoo report
        :param json_file_content: content of the cuckoo analysis report file
        :return: a list of signature references (found in a single report)
        """
        signature_references = []
        try:
            for signature in json_file_content["signatures"]:
                try:
                    for reference in signature["references"]:
                        signature_references.append(reference)
                except Exception:
                    # print("Exception occured in the file", report_json_path, "while reading signature references.")
                    e = Exception
        except Exception:
            # print("Exception occured in the file", report_json_path, "while reading signature references.")
            e = Exception
        return signature_references
    def sort_lists(self):
        """
        A function to sort unique lists.
        :return:
        """
        self.unique_api_calls = sorted(self.unique_api_calls)
        self.unique_dlls = sorted(self.unique_dlls)
        self.unique_dirs = sorted(self.unique_dirs)
        self.unique_mutexes = sorted(self.unique_mutexes)
        self.unique_strings = sorted(self.unique_strings)
        self.unique_drops = sorted(self.unique_drops)
        self.unique_drop_exts = sorted(self.unique_drop_exts)
        self.unique_regs = sorted(self.unique_regs)
        self.unique_files = sorted(self.unique_files)
        self.unique_file_exts = sorted(self.unique_file_exts)
        self.unique_signatures = sorted(self.unique_signatures)
        self.unique_signature_references = sorted(self.unique_signature_references)
        self.unique_drop_types = sorted(self.unique_drop_types)
        return
