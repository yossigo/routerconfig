import hashlib
import requests
import re
import telnetlib
import sys
import time
import socket

NEW_ADMIN_USER = 'admin'
NEW_ADMIN_PASSWORD = 'admin'

class RouterAuth(object):
    def __init__(self, url, user, hash2):
        self.url = 'http://10.0.0.138'
        self.user = user
        self.hash2 = hash2
        self.session = requests.Session()

    def get_login_params(self):
        login_page = self.session.get('%s/login.lp' % self.url).content
        var_pattern = re.compile('^var (\S+) = "(\S+)";')
        rn_pattern = re.compile('^.*input.*name="rn"\s+value="(\S+)"')

        login_params = {}
        for line in login_page.split('\n'):
            match = var_pattern.match(line)
            if match is not None:
                login_params[match.group(1)] = match.group(2)
                continue

            match = rn_pattern.match(line)
            if match is not None:
                login_params['rn'] = match.group(1)

        return login_params

    def get_field_name(self, uri, name):
        page = self.session.get('%s%s' % (self.url, uri))
        rn_pattern = re.compile('^.*input.*name=\'' + name + '\'\s+value=\'(\S+)\'')
        rn = None
        for line in page.content.split('\n'):
            match = rn_pattern.match(line)
            if match is not None:
                rn = match.group(1)
        return rn

    def authenticate(self):
        params = self.get_login_params()
        ha2 = hashlib.md5('GET' + ':' + params.get('uri')).hexdigest()
        hidepw = hashlib.md5(self.hash2 + ':' + params.get('nonce') +
                             ':' + '00000001' + ':' + 'xyz' + ':' + 
                             params.get('qop') + ':' + ha2).hexdigest()
        
        login_response = self.session.post(
            '%s%s' % (self.url, params.get('uri')),
            data={'user': self.user,
                  'hidepw': hidepw,
                  'rn': params.get('rn'),
                  'password': ''})
        if login_response.content.find('Logged in as') == -1:
            return False

        return True

    def create_user(self, user):
        f2 = self.get_field_name('/cgi/b/users/cfg/usraccaddrem/?tid=ADD_USER', '2')
        create_response = self.session.post(
            '%s/cgi/b/users/cfg/usraccedit/?be=0&l0=3&l1=9&tid=ADD_USER' % self.url,
            data={ 0: 10, 1: 'usrAccApply', '2': f2, 34: 'NewUser', 36: '1',
                33: user, 31: 'SuperUser' })

class RouterConfig(object):
    def __init__(self, addr, admin_user, admin_pass):
        self.addr = addr
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.conn = telnetlib.Telnet(addr, 23)

    def wait_online(self):
        while True:
            try:
                s = socket.create_connection((self.addr, 80), timeout=2)
            except Exception as err:
                time.sleep(2)
                continue

            break

    def docommand(self, cmd, timeout=5):
        self.conn.write(cmd + '\r\n')
        self.conn.read_until('}=>', timeout=timeout)

    def login(self):
        try:
            self.conn.read_until('Username :', timeout=5)
            self.conn.write(self.admin_user + '\r\n')
            self.conn.read_until('Password :', timeout=5)
            self.conn.write(self.admin_pass + '\r\n')
            self.conn.read_until('}=>', timeout=5)
            self.conn.write('\r\n')
            response = self.conn.read_until('}=>', timeout=5)
        except Exception:
            return False
        if response and response.find('Invalid') > -1:            
            return False
        return True

    def setup_users(self, admin_user, admin_password):
        self.docommand(':user delete name Bezeq')
        self.docommand(':user delete name tech')
        self.docommand(':user config name %s password=%s' % (admin_user, admin_password))

    def setup_telnet_access(self):
        self.docommand(':service system ifadd name=TELNET group=wan')
        
    def clean_router(self):
        self.docommand(':cwmp config state=disabled')
        self.docommand(':sntp delete name=ntp.bezek.com')
        self.docommand(':service system modify name=CWMP-C state=disabled')
        self.docommand(':service system modify name=CWMP-S state=disabled')
        self.docommand(':service system modify name=VOIP_SIP state=disabled')
        self.docommand(':ip ifdetach intf=CallBox')        
        self.docommand(':ip ifdelete intf=CallBox')
        self.docommand(':dns server flush')

    def setup_internet(self, user, password):
        self.docommand(':ppp ifdetach intf=Internet')
        self.docommand(':ppp ifconfig intf=Internet user=%s password=%s restart=enabled' %
            (user, password))
        self.docommand(':ppp ifattach intf=Internet')
        self.docommand(':ip ifconfig intf=Internet status=up')

    def setup_wifi(self, name, password):
        self.docommand(':wireless radio channel=1')
        self.docommand(':wireless mssid ifconfig ssid_id=0 ssid=%s apisolation=disabled secmode=wpa-psk WPAPSKkey=%s' % (
            name, password))

    def disable_telephony(self):
        self.docommand(':service system modify name=VOIP_SIP state=disabled')

    def setup_telephony(self, userid, password, primaddr='74.208.132.43', secaddr='74.208.9.132'):
        self.docommand(':service system modify name=VOIP_SIP state=enabled')
        self.docommand(':voice config intf=Internet static_intf=disabled sign_internal=external')
        self.docommand(':voice sip config transport=udp useragentdomain='' failbehaviour=continue')
        self.docommand(':voice sip config primproxyaddr=%s secproxyaddr=%s primregaddr=%s secregaddr=%s notifier_addr=%s' % (
            primaddr, secaddr, primaddr, secaddr, primaddr))
        self.docommand(':voice profile flush')
        self.docommand(':voice profile add SIP_URI=%s username=%s password=%s voiceport=FXS enable=enabled' % (
             userid, userid, password))
        self.docommand(':voice dialplan flush')
        self.docommand(':voice dialplan add prefix=0 defaultport=VoIP fallbackport=NA priority=NA fallback=0 minimumdigits=9 maximumdigits=13 posofmodify=1 remnumdigits=1 insert="011972" rescan=0 data=0 action=ROUTE_incl_eon')
        self.docommand(':voice dialplan add prefix=00 defaultport=VoIP fallbackport=NA priority=NA fallback=0 minimumdigits=12 maximumdigits=22 posofmodify=1 remnumdigits=2 insert="011" rescan=0 data=0 action=ROUTE_incl_eon')
        self.docommand(':voice dialplan add prefix=001 defaultport=VoIP fallbackport=NA priority=NA fallback=0 minimumdigits=13 maximumdigits=15 posofmodify=1 remnumdigits=2 insert="" rescan=0 data=0 action=ROUTE_incl_eon')
            
    def save(self):
        self.docommand('saveall', timeout=None)

def main():
    admin_user = NEW_ADMIN_USER
    admin_password = NEW_ADMIN_PASSWORD

    if len(sys.argv) > 1:
        router_addr = sys.argv[1]
        bypass_wait = True
    else:
        router_addr = '10.0.0.138'
        bypass_wait = False
    
    print '***************************************************************'
    print 'Bezeq Thomson TG797n v2 Configuration Tool'
    print 'Copyright (C) 2015 Yossi Gottlieb'
    print '***************************************************************'
    print ''
    print ''
    if not bypass_wait:
        print 'Waiting for router...'
        router_cfg = RouterConfig(router_addr, None, None)
        router_cfg.wait_online()
        router_cfg = None
        print 'Router found!'
    
    print 'Checking if router is locked...'
    router_cfg = RouterConfig(router_addr, admin_user, admin_password)
    if not router_cfg.login():
        print 'Router is locked, unlocking...'
        auth = RouterAuth('http://%s' % router_addr, 'Bezeq', 'ffc773c3a1206c10cdd4d017a26578ac')
        if not auth.authenticate():
            print 'Failed.  Please RESET router and try again.'
            sys.exit(1)

        print 'Changing configuration...'
        auth.create_user(admin_user)
        router_cfg = RouterConfig(router_addr, admin_user, admin_user)
        if not router_cfg.login():
            print 'Failed to configure.  Please RESET router and try again.'
            sys.exit(1)
        router_cfg.setup_users(admin_user, admin_password)
        router_cfg.clean_router()        
        router_cfg.setup_telnet_access()
        router_cfg.save()
        print 'Router is unlocked!'
    else:
        router_cfg.setup_telnet_access()
        print 'Router is OK, unlocked already.'

    while True:
        print ''
        print 'Select configuration:'
        print '[1] Wireless'
        print '[2] Internet'
        print '[3] Telephony'
        print '[4] Exit'
        print ''
        sys.stdout.write('==> ')
        choice = sys.stdin.readline().strip()
        
        if choice == '1':
            print 'Setting up wireless:'
    
            sys.stdout.write('WiFi name: ')
            wifi_name = sys.stdin.readline().strip()

            while True:
                sys.stdout.write('WiFi password: ')
                wifi_password = sys.stdin.readline().strip()
                if len(wifi_password) < 10:
                    print 'Too short, try again'
                else:
                    break
            
            print 'Changing Wireless configuration...'
            router_cfg.setup_wifi(wifi_name, wifi_password)        
            print 'Done, waiting for router to re-connect...'                       
            time.sleep(10)
            router_cfg.wait_online()
            print 'Router is now connected!'
            router_cfg = RouterConfig(router_addr, admin_user, admin_password)
            router_cfg.login()
            router_cfg.save()
            
        elif choice == '2':
            print 'Setting up Internet connection:'

            sys.stdout.write('Internet username: ')
            username = sys.stdin.readline()

            sys.stdout.write('Internet password: ')
            password = sys.stdin.readline()

            print 'Changing Internet configuration...'
            router_cfg.setup_internet(username, password)
            router_cfg.save()
            print 'Done.'
        elif choice == '3':
            print 'Setting up Telephony:'
        
            while True:
                sys.stdout.write('Enable telephony [y/n]?')
                yesno = sys.stdin.readline().strip()
                if yesno.lower() == 'n':
                    print 'Disabling telephony...'
                    router_cfg.disable_telephony()
                    router_cfg.save()
                    print 'Telephony is disabled.'
                    break
                elif yesno.lower() == 'y':                                
                    sys.stdout.write('User ID: ')
                    username = sys.stdin.readline().strip()
            
                    sys.stdout.write('Password: ')
                    password = sys.stdin.readline().strip()
            
                    print 'Changing Telephony configuration...'
                    router_cfg.setup_telephony(username, password)
                    router_cfg.save()
                    print 'Telephony is configured.'
                    break
                else:
                    print 'Please answer [y/n]'                
        elif choice == '4':
            break
        else:
            print 'Invalid choice'

if __name__ == '__main__':
    main()
