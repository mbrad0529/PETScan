import pefile
import argparse

parser = argparse.ArgumentParser(description="Analyzes target PE file and reports various file attributes.")
parser.add_argument("file", help="File to analyze")
parser.add_argument("-v", "--verbose", help="Increase command line output verbosity.", action="store_true")
parser.add_argument("-o", "--output", "-r", " --report", help="Output file to write results to, default is report.txt",
                    nargs="?", dest="outfile", action="store", default="report.txt", const="report.txt")
args = parser.parse_args()

