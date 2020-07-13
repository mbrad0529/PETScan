# PETScan

This is a simple proof of concept Windows Portable Executable (PE) file parser written in Python. This script utilizes functionality provided by PEView to parse various aspects of the provided file and generate a report. Future versions will include more advanced functionality and attempt to categorize a given executable as malicious or not.

# Platform
Though PE files are generally intended to be used only on Windows devices, this analysis script itself is Cross-Platform and can be executed on any system with a valid Python 3 installation (tested/built on Python 3.8) and the necessary PEFile and PrettyTables libraries installed.

# Environment
As mentioned in Platform, the device running the scripts needs a valid Python 3 installation, any version of Python above 3.0 should work, the scripts were tested against Python 3.8. Furthermore, the PEFile and PrettyTables (PTable) modules must be installed via `pip install pefile` and `pip install PTable`, respectively.

# Usage
The script requires at least one argument, the PE file to be analyzed. Additional options are available for generating a report (functionality coming in future release), choosing a deeper level of analysis (default is to only index Imports and Exports Data Directories) and to enable verbose output which provides detailed status messages at various stages of execution.

# Releases
1.0
* Initial Release.
* Support for generating Reports is not yet implemented, output redirection can be used to write data to a file.
