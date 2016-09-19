<%
    import os 

    OPENVPN_DIR = '/etc/local/openvpn'
    openvpn_conf = dispatcher.call_sync('service.openvpn.get_config')
    system_info = dispatcher.call_sync('system.general.get_config')

    if not os.path.isdir(OPENVPN_DIR):
        os.mkdir(OPENVPN_DIR)
    
    if openvpn_conf['mode'] == 'pki':
        ca_data = dispatcher.call_sync('crypto.certificate.query',
                                    [('id', '=', openvpn_conf['ca'])], {'single': True})
        
        openvpn_conf['ca'] = ca_data['certificate_path'].split('/')[-1]
        openvpn_conf['dev'] = openvpn_conf['dev'].rstrip('0123456789')

    CONFIG_MESSAGE = '''
# This is the OpenVPN client configuration file generated automatically by FreeNas.
# For pki scenario copy corresponding private key and certificate signed by valid certificate authority.
# If you are using tls-auth static key you have to copy and paste displayed key
# to the OpenVPN config directory and name it as "ta.key".
# The "remote" directive should contain the ip address of device which provide port redirection
# to the FreeNas appliance configured as OpenVPN server.
'''

%>\
% if openvpn_conf['mode'] == 'pki':
${CONFIG_MESSAGE}
client
dev ${openvpn_conf['dev']}
% if openvpn_conf['persist_key']:
persist-key
% endif
nobind
% if openvpn_conf['persist_tun']:
persist-tun
% endif
remote ${system_info['hostname']}
ca ${openvpn_conf['ca']}
cert signed certificate path
key corresponding private key path
% if openvpn_conf['tls_auth']:
tls-auth ta.key 1
% endif
cipher ${openvpn_conf['cipher']}
port ${openvpn_conf['port']}
proto ${openvpn_conf['proto']}
% if openvpn_conf['comp_lzo']:
comp-lzo
% endif
verb ${openvpn_conf['verb']}
% else:
${CONFIG_MESSAGE}
secret ta.key
remote ${system_info['hostname']}
dev ${openvpn_conf['dev']}
ifconfig ${openvpn_conf['psk_remote_ip']} ${openvpn_conf['psk_server_ip']}
port ${openvpn_conf['port']}
% endif

