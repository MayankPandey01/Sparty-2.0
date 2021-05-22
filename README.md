# Sparty-2.0

Sparty-2.0 is an  tool written in Python to audit web applications using Sharepoint and Frontpage Architecture. This Tool gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. 

![sparty](https://user-images.githubusercontent.com/29165227/119223005-c09a2680-bb14-11eb-86b8-b8eaf5c7e62e.PNG)



## Installation
- ` git clone https://github.com/MayankPandey01/Sparty-2.0.git`

## Recommended Python Version:
This Tool Only Supports Python 3.
The recommended version for Python 3 is 3.8.x.

## Dependencies:

The dependencies can be installed using the requirements file:.

Installation on Windows:.
- python.exe -m pip install -r requirements.txt.

Installation on Linux.
- sudo pip install -r requirements.txt.

## How it Works
This Tool uses 2 modules to Audit  SharePoint, `Exploitation  ` and `Enumeration`
You can use one or both of them at once. `python Sparty-2.0 -u https://example.com -enum -exploit `

> Enumeration Module

- Frontpage RPC Check
- Frontpage Service Listing
- Frontpage Config Check
- Fingerprint Frontpage
- Checks Fpr Exposed Services in the Frontpage/Sharepoint  Directory
- Sharepoint and Frontpage Version Detection!
- Exposed Directory Check!
- Installed File and Access Rights Check!
- RPC Service Querying!
- File Enumeration!

> Exploitation Module

- Dumps Sharepoint Headers
- Dumps Password Files
- Checks For FIle Upload
- Remove Frontpage Folder


## Please take this into consideration

1. Always specify https | http explcitly !
2. Always provide the proper directory structure where sharepoint/frontpage is installed !
3. Do not specify '/' at the end of url !

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
url           | url           | A URL to scan 
-enum            | Enumeration| Uses Enumeration Module
-exploit            | Exploitation  | Uses Exploitation Module
-h            | --help        | Displays help 


### Note
- Original Version Of Sparty https://github.com/adityaks/sparty
- This Tool may throw some False Positive , always double check the Output.

Use This Tool Wisely.\
Happy Hacking :sparkles: :sparkles:
