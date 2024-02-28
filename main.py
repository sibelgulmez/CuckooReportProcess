from dataset import dataset
from writer import writer

if __name__ == "__main__":
    ransomware_dataset = dataset("", True)
    benign_dataset = dataset("", True)
    w = writer(ransomware_dataset, benign_dataset)
    w.write("", "")