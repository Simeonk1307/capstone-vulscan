# VulScan: A Deep Learning-based Vulnerability Scanning Tool for C/C++ files

### Run the tool
To run the VulScan executable, open terminal in the directory where **vulscan.zip** is extracted (_PATH_). In the terminal window, type the following command to run the tool:
> **\<PATH> $ ./vulscan**

Wait until the executable unpacks the tool and the input interface pops up. This typically takes around a minute or so; be patient.

### Input
VulScan's input interface allows the user to input either a single source code file or a complete directory containing multiple source code file. Please specify your input accordingly.
> NOTE: Currently, only C/C++ source code files are accepted by the tool.

Wait until VulScan scans the input file(s) for vulnerabilties. This typically takes around 10-15 seconds for a single file and the time varies accordingly in case of a directory input.

### Output
The output will a vulnerability report with the name - **vulscan_report_<_file_name_>.pdf** for each file input to VulScan. This report can be found at the original directory location where the source code file exists.

##### - For more information regarding the VulScan tool, please refer to the **"VulScan_Manual.pdf"** available in the same directory.