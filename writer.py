import csv
from dataset import dataset
from sample import sample
import os

class writer:
    """
    A class to write the data into a csv file
    """
    def __init__(self, ransomware_dataset, benign_dataset):
        """
        :param ransomware_dataset: Dataset object of ransomware samples
        :param benign_dataset: Dataset object of benign samples
        """
        self.ransomware_dataset = ransomware_dataset
        self.benign_dataset = benign_dataset

        self.header = []
        self.content = []

        self.api_calls = []
        self.dlls = []
        self.dirs = []
        self.mutexes = []
        self.strings = []
        self.drops = []
        self.drop_exts = []
        self.drop_types = []
        self.regs = []
        self.files = []
        self.file_exts = []
        self.signatures = []
        self.signature_references = []

        self.fill_header()
        self.fill_content()
    def fill_header(self):
        """
        A function to fill the header of the csv file and also the empty lists of the class
        :return:
        """

        # the first column is "class"
        self.header.append("CLASS")

        # api calls
        self.api_calls = self.ransomware_dataset.unique_api_calls + self.benign_dataset.unique_api_calls
        self.api_calls = sorted(list(set(self.api_calls)))
        for api_call in self.api_calls:
            self.header.append("API:" + api_call)

        # dlls
        self.dlls = self.ransomware_dataset.unique_dlls + self.benign_dataset.unique_dlls
        self.dlls = sorted(list(set(self.dlls)))
        for dll in self.dlls:
            self.header.append("DLL:" + dll)

        # drops
        self.drops = self.ransomware_dataset.unique_drops + self.benign_dataset.unique_drops
        self.drops = sorted(list(set(self.drops)))
        for drop in self.drops:
            self.header.append("DROP:" + drop)

        # drop extentions
        self.drop_exts = self.ransomware_dataset.unique_drop_exts + self.benign_dataset.unique_drop_exts
        self.drop_exts = sorted(list(set(self.drop_exts)))
        for drop_ext in self.drop_exts:
            self.header.append("DROP_EXT:" + drop_ext)


        # drop types
        self.drop_types = self.ransomware_dataset.unique_drop_types + self.benign_dataset.unique_drop_types
        self.drop_types = sorted(list(set(self.drop_types)))
        for drop_type in self.drop_types:
            self.header.append("DROP_TYPE:" + drop_type)

        # regs
        self.regs = self.ransomware_dataset.unique_regs + self.benign_dataset.unique_regs
        self.regs = sorted(list(set(self.regs)))
        for reg in self.regs:
            self.header.append("REG:" + reg)


        # files
        self.files = self.ransomware_dataset.unique_files + self.benign_dataset.unique_files
        self.files = sorted(list(set(self.files)))
        for file in self.files:
            self.header.append("FILE:" + file)

        # file_exts
        self.file_exts = self.ransomware_dataset.unique_file_exts + self.benign_dataset.unique_file_exts
        self.file_exts = sorted(list(set(self.file_exts)))
        for file_ext in self.file_exts:
            self.header.append("FILE_EXT:" + file_ext)

        # dirs
        self.dirs = self.ransomware_dataset.unique_dirs + self.benign_dataset.unique_dirs
        self.dirs = sorted(list(set(self.dirs)))
        for dir in self.dirs:
            self.header.append("DIR:" + dir)

        # strings
        self.strings = self.ransomware_dataset.unique_strings + self.benign_dataset.unique_strings
        self.strings = sorted(list(set(self.strings)))
        for string in self.strings:
            self.header.append("STRING:" + string)

        # mutexes
        self.mutexes = self.ransomware_dataset.unique_mutexes + self.benign_dataset.unique_mutexes
        self.mutexes = sorted(list(set(self.mutexes)))
        for mutex in self.mutexes:
            self.header.append("MUTEX:" + mutex)

        # signatures
        self.signatures = self.ransomware_dataset.unique_signatures + self.benign_dataset.unique_signatures
        self.signatures = sorted(list(set(self.signatures)))
        for signature in self.signatures:
            self.header.append("SIGNATURE:" + signature)

        # signature references
        self.signature_references = self.ransomware_dataset.unique_signature_references + self.benign_dataset.unique_signature_references
        self.signature_references = sorted(list(set(self.signature_references)))
        for signature_reference in self.signature_references:
            self.header.append("SIGNATURE_REFERENCE:" + signature_reference)
        print("Filled header.")
    def fill_content(self):
        """
        A function to fill the csv content
        :return:
        """
        # ransomware
        for json_path in self.ransomware_dataset.json_paths:
            ransomware_content = [1] # the first column is 1 for ransomware samples (column of "class")
            ransomware_sample = sample(json_path)

            # api call
            for api_call in self.api_calls:
                if api_call in ransomware_sample.api_calls:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # dll
            for dll in self.dlls:
                if dll in ransomware_sample.dlls:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # drop
            for drop in self.drops:
                if drop in ransomware_sample.drops:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # drop_ext
            for drop_ext in self.drop_exts:
                if drop_ext in ransomware_sample.drop_exts:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # drop_type
            for drop_type in self.drop_types:
                if drop_type in ransomware_sample.drop_types:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # reg
            for reg in self.regs:
                if reg in ransomware_sample.regs:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # file
            for file in self.files:
                if file in ransomware_sample.files:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # file_ext
            for file_ext in self.file_exts:
                if file_ext in ransomware_sample.file_exts:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # dir
            for dir in self.dirs:
                if dir in ransomware_sample.dirs:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # string
            for string in self.strings:
                if string in ransomware_sample.strings:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)

            # mutex
            for mutex in self.mutexes:
                if mutex in ransomware_sample.mutexes:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)


            # signature
            for signature in self.signatures:
                if signature in ransomware_sample.signatures:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)


            # signature reference
            for signature_reference in self.signature_references:
                if signature_reference in ransomware_sample.signature_references:
                    ransomware_content.append(1)
                else:
                    ransomware_content.append(0)


            self.content.append(ransomware_content)
        print("Filled ransomware content.")

        # benign
        for json_path in self.benign_dataset.json_paths:
            benign_content = [0] # the first column is 0 for benign samples (column of "class")
            benign_sample = sample(json_path)

            # api call
            for api_call in self.api_calls:
                if api_call in benign_sample.api_calls:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # dll
            for dll in self.dlls:
                if dll in benign_sample.dlls:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # drop
            for drop in self.drops:
                if drop in benign_sample.drops:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # drop_ext
            for drop_ext in self.drop_exts:
                if drop_ext in benign_sample.drop_exts:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # drop_type
            for drop_type in self.drop_types:
                if drop_type in benign_sample.drop_types:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # reg
            for reg in self.regs:
                if reg in benign_sample.regs:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # file
            for file in self.files:
                if file in benign_sample.files:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # file_ext
            for file_ext in self.file_exts:
                if file_ext in benign_sample.file_exts:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # dir
            for dir in self.dirs:
                if dir in benign_sample.dirs:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # string
            for string in self.strings:
                if string in benign_sample.strings:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            # mutex
            for mutex in self.mutexes:
                if mutex in benign_sample.mutexes:
                    benign_content.append(1)
                else:
                    benign_content.append(0)


            # signature
            for signature in self.signatures:
                if signature in benign_sample.signatures:
                    benign_content.append(1)
                else:
                    benign_content.append(0)


            # signature reference
            for signature_reference in self.signature_references:
                if signature_reference in benign_sample.signature_references:
                    benign_content.append(1)
                else:
                    benign_content.append(0)

            self.content.append(benign_content)
        print("Filled benign content.")
    def write(self, directory, filename):
        """
        A function to write .csv and .txt files
        :param directory: directory of the files to be written
        :param filename: name of the files to be written
        :return:
        """
        # csv file
        filename = os.path.join(directory, filename + ".csv")
        try:
            with open(filename, 'w', newline='') as f:
                csv_writer = csv.writer(f)
                csv_writer.writerow(self.header)
                csv_writer.writerows(self.content)
            print(filename, "has been written successfully.")
        except Exception:
            print("Error occured while writing csv file.")


        filename = filename.replace(".csv", "_variables.txt")
        try:
            with open(filename, 'w') as f:
                for line in self.header:
                    f.write(f"{line}\n")
            print(filename, "has been written successfully.")
        except Exception:
            print("Error occured while writing text file.")

