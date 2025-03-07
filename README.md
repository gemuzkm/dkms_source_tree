# Package Installation

All necessary packages are installed automatically when the agent is installed. If needed, you can install them separately:

    ```bash
    sudo yum update
    ```
    ```bash
    sudo yum install kernel-devel gcc make elfutils-libelf-devel
    ```

# Installing the Custom SnapAPI Module 1.0.7 on RHEL 6.10

This guide provides step-by-step instructions for installing the custom SnapAPI module version 1.0.7 on Linux RHEL 6.10 (kernel 2.6.32).

## Prerequisites

- Ensure you have root privileges or sufficient permissions to execute the commands.
- Acronis should be installed on your system.

## Installation Steps

1. **Open the Terminal**

   Open your terminal (console).

2. **Stop Acronis Processes**

   Execute the following command to stop Acronis processes:

    ```bash
   /etc/init.d/acronis_mms stop
    ```

  Alternatively, you can use:
    
  ```bash 
  systemctl stop acronis_mms
   ```

3. Remove the SnapAPI Module from the Kernel Run the command

    ```bash
    rmmod snapapi26
    ```

4. Check SnapAPI Version in DKMS Tree Verify the SnapAPI version with:

    ```bash
    dkms status
    ```

Look for an entry similar to:
  snapapi26, 1.0.7, 2.6.32-754.35.1.el6.x86_64, x86_64: installed

5. Remove SnapAPI from DKMS Tree
   Remove SnapAPI using the version found in the previous step:

    ```bash
    dkms remove -m snapapi26 -v 1.0.7 --all
    ```

6. Clean Up Source Files Remove any existing source files:

    ```bash
    rm -rf /usr/src/snapapi*
    ```

7. Clone the Repository Clone the DKMS source tree repository:

    ```bash 
    git clone https://github.com/gemuzkm/dkms_source_tree.git
    ```
    ```bash
    cd dkms_source_tree
    ```
9. Add to DKMS Tree Add the cloned source to the DKMS tree:

    ```bash
    dkms add .
    ```

11. Build and Install the SnapAPI Module Build and install the SnapAPI module with:

    ```bash
    dkms build -m snapapi26 -v 1.0.7
    ```
    ```bash
    dkms install -m snapapi26 -v 1.0.7
    ```

12. Load the SnapAPI Kernel Module Load the module using:

    ```bash
    sudo modprobe snapapi26
    ```

14. Start Acronis Processes Restart Acronis processes:

    ```bash
    systemctl start acronis_mms
    ```

Conclusion
You have successfully installed the SnapAPI module 1.0.7 on RHEL 6.10. If you encounter any issues, please refer to the documentation or seek assistance.
