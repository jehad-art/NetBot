# NetBot - An Automated Router Hardening Solution for Small to Medium Enterprises

<h2>Abstract</h2>
Hardening the configuration of network assets has become an essential practice for both General-Purpose and Special-Purpose Operating Systems. Security regulations and standards mandate this process to minimize the risk of misconfiguration, which can lead to significant operational and security vulnerabilities. Misconfigurations leave networks exposed to various types of attacks, compromising the confidentiality, integrity, and availability (CIA) of critical assets. Network administrators often lack the specialized expertise required to implement security configurations, as their primary focus is typically on maintaining network performance and operational efficiency.

here, we are proposing a passive, automated solution for hardening the configurations of Special-Purpose network systems. The solution identifies critical assets and analyzes them for potential misconfigurations. It is designed to address all aspects of network security, including asset configuration, architectural segmentation, and Defense-In-Depth strategies.

This is an implementation of the paper made by H. M. D. G. V. Perera et al.[1]<br>

## Table of Content

- [Prerequisites](#Prerequisites)
- [Table of Content](#table-of-content)
- [Environment Preparation](#Environment-Preparation)
- [Virtual Network topology](#Virtual-Network-topology)
- [Getting Started](#Getting-Started)
- [Expected Output](#Expected-Output)

## Prerequisites
<h3>Software Requirements</h3>
<b>Python: </b>Version 3.8 or higher.<br>
<b>Libraries:</b><br>
        &emsp; - json (for configuration structure)<br>
        &emsp; - pretteytable (for data tabular view)<br>
        &emsp; - netmiko (for network access)<br>
        &emsp; - GNS3 (for network emulation)<br>
        &emsp; - GNS3 VM (Hosting VM and separating network adapters)<br>
    <b>Automation Tools:</b><br>
        &emsp; - Ansible (for large-scale router configuration management, optional)<br>

<h3>Hardware Requirements</h3>
<b>System:</b><br>
   &emsp; - Minimum 4 GB of RAM.<br>
   &emsp; - Minimum 2 GHz dual-core CPU.<br>
<b>Network:</b><br>
   &emsp; - Stable internet connection for fetching vulnerability updates and remote SSH access.<br>

## Environment Preparation
<b>Install Network Emulation (GNS3)::</b><br>
- Install the client.<br>
- Install GNS3 VM.<br>
- Configure the network setting in vmware to make it bridge network.<br>
- Make sure the vm ip in the same subnet of the host’s.<br>
- After client finishes installation, in the setup wizard, choose <b style="color:#006633;">“run appliance in a virtual machine” </b>.<br>
- Install Cisco C3745 IOS v12.3.<br>
- Configure the preferences to add the run through local vm<br>
- Add a new template device with the installed image<br>
- Creating a loopback adapter and connect it through cloud template<br><br>

![image](https://github.com/user-attachments/assets/f0ee65b9-2660-418e-a7cb-6dc3d70b9260)
<br><br><br>
![image](https://github.com/user-attachments/assets/62e196fa-f1d4-4b22-be9f-797eaa22516f)<br>
<p>Figure: Required settings for GNS3 VM</p>

## Virtual Network topology
<img src="https://github.com/user-attachments/assets/c934e534-911c-4986-8429-889e5e0d1687" />

<br>
<p align='center'>Figure: The somulated network topology</p>
<br>
<h2>Initial Configuration</h2>
<b>Sample configuration applied to the router</b><br>
<img src="https://github.com/user-attachments/assets/309f22d4-7234-419e-9707-3bef64f04a8a" /><br>
<p>Figure: snippet of sample Cisco IOSv12 configuration</p><br>

## Getting Started
### Download the code locally
Using the `git` command from the terminal:

```bash
$ git clone https://github.com/jehad-art/NetOrb.git
```

or by clicking on `Code >> Local >> Download ZIP` on the repository main page.

### Install required Packages
You can install all these dependencies using `pip`:<br>
`Netmiko`<br>
```bash
pip install netmiko 
```
`prettytable`<br>
```bash
python -m pip install -U prettytable 
```
### Implementation code structure
The code structured into the following files:<br>
- `Extract_config.py` (to extract the router configuration to a string variable)<br>
- `Original_config.txt` (the extracted config)<br>
- `Structure_config.py` (to read the extracted config and convert it to final json form)<br>
- `Config_C3745.json` (structure file to be analyzed)<br>
- `Analyze_config.py` (to analyze the structured file line by line and identify the misconfiguration and suggested fixes)<br>
- `Print_config.py` (print the resultant output in a tabular format for human readable)<br>
- `Main.py` (the main file to call all previous functions in and run it)<br>


### Required changes
After installation and preparating the prerequisites, open the `Extract_config.py` file and update the router ip address, username and password to match your set of configured access in the router:<br>
```bash
from netmiko import ConnectHandler
def extract_connfig(output):
    device = ConnectHandler(device_type='cisco_ios', ip='<your router ip>', username='<router username>', password='<router password>')
    output = device.send_command("show run")
    device.disconnect() 
```
Once this done, just open the file `main.py` and run it. or you can make yours and add the following code:<br>
```bash
from extract_config import *
from structure_config import *
from analyze_config import *
from print_config import *
output = ""
extract_connfig(output)
structure(output)
analyze(output)
printing(output)
```

## Expected Output
Sample output for the implemented work:<br>

<img src="https://github.com/user-attachments/assets/00cda780-d3a4-4f8b-aea6-6bb20edcce4e" /><br>
<p align='center'>Figure: The output of a sample router's configuration result</p><br><br>


[![image](https://github.com/user-attachments/assets/adf50973-c55f-4203-a40c-7f2385a479cf)](https://youtu.be/Q3LzE3wRGoY)


## References
[1] <a href="https://ieeexplore.ieee.org/document/9623186"> H. M. D. G. V. Perera, K. M. Samarasekara, I. U. K. Hewamanna, D. N. W. Kasthuriarachchi, K. Y. Abeywardena and K. Yapa, "NetBot - An Automated Router Hardening Solution for Small to Medium Enterprises," 2021 IEEE 12th Annual Information Technology, Electronics and Mobile Communication Conference (IEMCON), Vancouver, BC, Canada, 2021 </a>

