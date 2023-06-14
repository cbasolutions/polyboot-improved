# polyboot-improved
Script for managing Poly phones via the web interface

usage:

python3 polyboot-improved.py [options]
- Options func, host, and password are required for single use.  
- Option ifile can be used with or without ofile.  
- Option template will create a template in for the ifile in the current working directory.  
    

options:  

* -h, --help
    - show this help message and exit. </br>
* -i IFILE, --ifile IFILE.  </br>
    - Input filename for bulk operations. CSV file with headers: host,password,function. Host is either host or IP. </br>
* -f FUNCTION, --function FUNCTION. </br>
    - Poly form-submit function to run.  </br>
* -a HOST, --host HOST 
    - Hostname or IP for single operation.  </br>
* -p PASSWORD, --password PASSWORD. </br>
    - Password for device in single operation mode.  </br>
* -o OFILE, --ofile OFILE
    - Output filename for logging.
* -t, --template
    - Create CSV template for bulk operation.
