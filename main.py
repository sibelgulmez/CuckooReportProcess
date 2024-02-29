from dataset import dataset
from writer import writer

if __name__ == "__main__":
    ransomware = dataset("", True)
    benign = dataset("", True)
    w = writer(ransomware, benign)
    w.write("", "")