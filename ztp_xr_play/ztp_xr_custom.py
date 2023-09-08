#! /usr/bin/env python3
"""
 ztp_xr_custom

 Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 @version 1.27, 23/03/2023
"""
import sys
import os
import logging
import json
import re
import socket
import base64
import time
import tempfile
import ssl
import urllib.parse as urlparser
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from functools import partial

sys.path.append("/pkg/bin/")
from ztp_helper import ZtpHelpers

SYSLOG_CONFIG = {
    'syslog_file': '/root/ztp_python.log',
    'syslog_server': '198.18.201.16',
    'syslog_port': 514
}

CONFIG = {
    "base_url": "https://9.0.12.154:30603",
    "cnc_username": "admin2",
    "cnc_password": "SP!nvlab1",
    "day0_config_id": "2d48f955-3eec-4495-ac71-5e37a8b20f18",
    "golden_label": "7.8.1",
    "golden_image_id": "cw-image-uuid-2514cf83-3f4d-4ce1-8463-0818d7c07d94",
    "use_ipxe": True,
    "day0_config_replace": True,
    "ztp_interface_name": "MgmtEth0/RP0/CPU0/0",
    "root_user": "admin",
    "root_password": "$6$N8waO/0jdKPe3O/.$oYCFbNgtzrtBzz2O4Jp2K.9x3CaQLmBX/WE3C3NJay0EQJa6kWPB3pnpCdHvUJPZeJdpavzDTDXvGsV.ogKWS0",
    "notify_url": "https://9.0.13.23/bpa/api/v2.0/device-activation/activate-device/",
    "notify_apikey": "7a5ff0e062e03f64b3137115a1cf5f6d",
    "nso_sync_from": True
}

CONFIG_DEFAULTS = {
    "notify_url": None,
    "notify_username": None,
    "notify_password": None,
    "notify_apikey": None,
    "use_ipxe": False,
    "day0_config_reboot": False,
    "day0_config_replace": False,
    "fpd_check": False,
    "root_user": None,
    "root_password": None,
    "ztp_interface_vrf": None,
    "ztp_interface_name": None,
    "cnc_username": None,
    "cnc_password": None,
    "cnc_cdg_name": None,
    "nso_sync_from": False
}


def main():
    ztp_api = ZtpApi(**SYSLOG_CONFIG)

    ztp_api.log_info('Loading metadata')
    meta = ZtpMetadata(defaults=CONFIG_DEFAULTS, **CONFIG)

    notify_credentials = {
        'username': meta.notify_username,
        'password': meta.notify_password,
        'apikey': meta.notify_apikey
    }

    if meta.notify_url:
        ztp_api.log_info('REST notification enabled')

    # Enable verbose debugging to stdout/console
    ztp_api.toggle_debug(True)

    ztp_api.log_info('Checking whether software upgrade is needed')
    running_label = ztp_api.get_running_label()
    ztp_api.log_info(f'Running: {running_label}, Golden: {meta.golden_label}')
    if running_label in (label.strip() for label in meta.golden_label.split(' or ')):
        ztp_api.log_info('No upgrade needed')
    elif meta.use_ipxe:
        ztp_api.log_info('Installing new image via iPXE boot')
        ztp_api.install_ipxe()
        # Device will reload, need to exit ZTP at this point
        ztp_api.log_info('ZTP stopped for iPXE boot')
        return
    else:
        ztp_api.log_info(f'Installing "{meta.golden_image_id}" image')
        ztp_api.install_image(meta.base_url, meta.golden_image_id)

    ztp_api.log_info('Wait for any in-progress auto FPD upgrades to complete')
    ztp_api.fpd_upgrade_wait()

    if meta.fpd_check:
        ztp_api.log_info('Initiating FPD upgrades')
        ztp_api.upgrade_fpd()
        ztp_api.log_info('Wait for FPD upgrades to complete')
        # Adding an extra wait in order for sh hw-module fpd to reflect the fpd upgrade status
        time.sleep(30)
        ztp_api.fpd_upgrade_wait()

        if not meta.day0_config_reboot:
            ztp_api.router_reload()
            ztp_api.log_info('ZTP stopped for reload after FPD upgrade')
            return

    ztp_api.log_info('Create crypto keys if needed')
    ztp_api.set_crypto_keys()

    if meta.root_user and meta.root_password:
        ztp_api.log_info('Configuring root credentials')
        ztp_api.set_root_user(user=meta.root_user, password=meta.root_password)

    ztp_api.log_info('Loading day0 configuration')
    try:
        ztp_api.load_config(meta.base_url, meta.day0_config_id, replace=meta.day0_config_replace)
        ztp_api.log_info('Day0 configuration load successful')

        ztp_api.log_info('Onboarding device to CNC')
        if not meta.ztp_interface_name:
            raise ZTPErrorException('Cannot get Mgmt interface address because "ztp_interface_name" was not provided')
        ztp_api.notify_cnc_success(meta.base_url, meta.ztp_interface_vrf, meta.ztp_interface_name)

    except ZTPErrorException as e:
        ztp_api.log_error(f"Day0 configuration load failed: {e}")
        ztp_api.notify_cnc_failure(meta.base_url)

    else:
        with CncApi(meta.base_url, username=meta.cnc_username, password=meta.cnc_password) as cnc_api:
            for retry in range(CncApi.MAX_RETRIES):
                ztp_api.log_info('Mapping device to CNC DG')

                node_uuid = cnc_api.get_node_uuid(ztp_api.chassis_sn)
                cdg_vuuid = cnc_api.get_cdg_vuuid(meta.cnc_cdg_name)
                if node_uuid and cdg_vuuid:
                    cnc_api.set_node_cdg_map(node_uuid, cdg_vuuid)
                    ztp_api.log_info(f'Mapping completed')
                    if meta.nso_sync_from:
                        ztp_api.log_info(f'Waiting {4 * CncApi.SLEEP_SECS}s to initiate sync-from')
                        time.sleep(4 * CncApi.SLEEP_SECS)
                        cnc_api.nso_sync_from(node_uuid)
                    break

                ztp_api.log_info(f'Device is not ready in CNC, will retry in {CncApi.SLEEP_SECS}s')
                time.sleep(CncApi.SLEEP_SECS)
            else:
                if node_uuid is None:
                    raise ZTPErrorException('Error getting node uuid from CNC')
                if cdg_vuuid is None:
                    raise ZTPErrorException('Error getting CDG vuuid from CNC')

        ztp_api.notify(meta.notify_url, **notify_credentials)

        if meta.day0_config_reboot:
            ztp_api.log_info('Custom ZTP process complete, will now reload the device')
            ztp_api.router_reload()
            return

        ztp_api.log_info('Custom ZTP process complete')


class ZtpApi(ZtpHelpers):
    def __init__(self, *args, **kwargs):
        super(ZtpApi, self).__init__(*args, **kwargs)
        self.chassis_sn = self._get_chassis_sn()
        self.log_label = f'[{self.chassis_sn}]: '

    def log_info(self, log_msg):
        self.syslogger.info(f'{self.log_label}{log_msg}')

    def log_error(self, log_msg):
        self.syslogger.error(f'{self.log_label}{log_msg}')

    def get_running_label(self):
        show_version = self.xrcmd({"exec_cmd": "show version"})
        if not succeeded(show_version):
            raise ZTPErrorException('"show version" command failed')

        regex = re.compile(r'Label\s+:\s*(.+?)\s*$')
        for line in show_version['output']:
            match = regex.match(line)
            if match:
                return match.group(1)
        else:
            raise ZTPErrorException('"show version" command parse failed')

    def _get_chassis_sn(self):
        show_inventory = self.xrcmd({"exec_cmd": "show inventory"})
        if not succeeded(show_inventory):
            raise ZTPErrorException('"show inventory" command failed')

        found_rack = False
        for line in show_inventory['output']:
            if not line.strip():
                continue
            if found_rack:
                match = re.search(r'SN:\s+(\S+)', line)
                if match:
                    return match.group(1)
                else:
                    found_rack = False
            if "Rack 0" in line:
                found_rack = True

        else:
            raise ZTPErrorException('"show inventory" command parse failed')

    def get_interface_ipv4(self, vrf, interface):
        exec_cmd = f"show ipv4 interface {interface}" if vrf is None else f"show ipv4 vrf {vrf} interface {interface}"

        show_interface = self.xrcmd({"exec_cmd": exec_cmd})
        if not succeeded(show_interface):
            raise ZTPErrorException('"show ipv4 interface" command failed')

        regex = re.compile(r'Internet\s+address\s+is\s+(\d+\.\d+\.\d+\.\d+)/(\d+)')
        for line in show_interface['output']:
            match = regex.search(line)
            if match:
                return match.group(1), int(match.group(2))
        else:
            raise ZTPErrorException('"show ipv4 interface" command parse failed')

    def get_hostname(self):
        show_run_host = self.xrcmd({"exec_cmd": "show running-config hostname"})
        if not succeeded(show_run_host):
            raise ZTPErrorException('"show running-config hostname" command failed')

        regex = re.compile(r'hostname\s+(\S+)')
        for line in show_run_host['output']:
            match = regex.search(line)
            if match:
                return match.group(1)
        else:
            raise ZTPErrorException('"show running-config hostname" command parse failed')

    def set_root_user(self, user, password):
        """ Sets the root user for IOS-XR during ZTP
        """
        config = [
            '!',
            f'username {user}',
            'group root-lr',
            'group cisco-support',
            f'secret 10 {password}',
            '!',
            'end'
        ]
        with tempfile.NamedTemporaryFile(delete=True) as f:
            f.write('\n'.join(config).encode())
            f.flush()
            f.seek(0)
            result = self.xrapply(f.name)

            if not succeeded(result):
                self.log_info(f'Failed to set root user: {json.dumps(result)}')

    def set_crypto_keys(self):
        show_pubkey = self.xrcmd({"exec_cmd": "show crypto key mypubkey rsa"})
        if not succeeded(show_pubkey):
            self.log_info(f"Unable to get the status of RSA keys: {show_pubkey['output']}")
            return

        if show_pubkey["output"] == '':
            self.log_info("No RSA keys present. Creating...")
            self.xrcmd({"exec_cmd": "crypto key generate rsa", "prompt_response": "2048\\n"})
        else:
            self.log_info("RSA keys already present. No need to create.")

    def load_config(self, cnc_url, config_id, replace=True, target_file='/disk0:/ztp/customer/downloaded-config'):
        # Download config from CNC
        request = Request(f"{cnc_url}/crosswork/configsvc/v1/configs/device/files/{config_id}")
        request.add_header('X-cisco-serial*', self.chassis_sn)
        download_data = http_request(request, http_context(cnc_url))

        with open(target_file, 'wb') as f:
            f.write(download_data)

        # Apply config to device
        apply_config = self.xrreplace(target_file) if replace else self.xrapply(target_file, 'Add ZTP configuration')
        if not succeeded(apply_config):
            raise ZTPErrorException('Error applying day0 config')

        return {"status": "success", "output": "configuration loaded successfully"}

    def install_image(self, cnc_url, image_id, target_folder='/harddisk:'):
        url = f"{cnc_url}/crosswork/imagesvc/v1/device/files/{image_id}"
        filename = os.path.basename(urlparser.urlsplit(url).path)
        target = os.path.join(target_folder, filename)

        if os.path.exists(target):
            self.log_info(f'Image already on {target_folder}, skipping download')
        else:
            download = self.download_file(url, target_folder)
            if not succeeded(download):
                raise ZTPErrorException('Error downloading image')
            self.log_info('Image download complete')

        install = self.xrcmd({"exec_cmd": f"install replace {target} noprompt commit"})
        if not succeeded(install):
            raise ZTPErrorException('Error installing image')

        self.log_info('Waiting for install operation to complete')
        wait_complete = self.wait_for('show install request', parse_show_install)
        if not succeeded(wait_complete):
            raise ZTPErrorException(f"Error installing image, {wait_complete['output']}")
        self.log_info('Install operation completed successfully')

        return {"status": "success", "output": "image successfully installed"}

    def install_ipxe(self):
        install = self.xrcmd({"exec_cmd": "reload bootmedia network location all noprompt"})
        if not succeeded(install):
            raise ZTPErrorException('Error issuing iPXE boot command')

        return {"status": "success", "output": "ipxe boot command successfully executed"}

    def fpd_upgrade_wait(self):
        wait_complete = self.wait_for('show hw-module fpd', parse_show_hwmodule)
        if not succeeded(wait_complete):
            raise ZTPErrorException(f"Error waiting fpd upgrades to complete, {wait_complete['output']}")

        wait_complete = self.wait_for('show platform', partial(parse_show_platform, {'IOS XR RUN', 'OPERATIONAL'}))
        if not succeeded(wait_complete):
            raise ZTPErrorException(f"Error waiting fpd upgrades to complete, {wait_complete['output']}")
        return {"status": "success", "output": "FPD upgrade wait successful"}

    def upgrade_fpd(self):
        fpd_upgrade = self.xrcmd({"exec_cmd": "upgrade hw-module location all fpd all"})
        if not succeeded(fpd_upgrade):
            raise ZTPErrorException('Error upgrading FPDs')

        return {"status": "success", "output": "FPD upgrade successful"}

    def router_reload(self):
        device_reload = self.xrcmd({"exec_cmd": "reload location all noprompt"})
        if not succeeded(device_reload):
            raise ZTPErrorException('Error issuing the reload command')

        return {"status": "success", "output": "Reload command successful"}

    def wait_for(self, cmd, cmd_parser, budget=1800, interval=15, max_retries=3):
        time_budget = budget
        fail_retries = 0
        while True:
            cmd_result = self.xrcmd({"exec_cmd": cmd})
            if not succeeded(cmd_result):
                if fail_retries < max_retries:
                    self.log_error(f'"{cmd}" command failed, will retry')
                    fail_retries += 1
                    continue
                raise ZTPErrorException(f'"{cmd}" command failed')

            done_waiting, is_success = cmd_parser(cmd_result['output'])

            if done_waiting and is_success:
                return {"status": "success", "output": f"'{cmd}' wait completed with success"}
            if done_waiting:
                return {"status": "error", "output": f"'{cmd}' wait completed with error"}

            time_budget -= interval
            if time_budget > 0:
                self.log_info('Waiting...')
                time.sleep(interval)
            else:
                self.log_info('Wait time budget expired')
                break

        return {"status": "error", "output": "wait time budget expired"}

    def notify(self, notify_url, **notify_credentials):
        if notify_url is None:
            return

        result = rest_callback(notify_url, {"serialNo": self.chassis_sn}, **notify_credentials)
        if not succeeded(result):
            self.log_error(f"REST callback failed: {result['output']}")
        else:
            self.log_info("REST callback sent")

        return

    def notify_cnc_success(self, cnc_url, interface_vrf, interface_name):
        ipv4_addr, ipv4_len = self.get_interface_ipv4(interface_vrf, interface_name)
        hostname = self.get_hostname()

        payload = {
            "ipAddress": {
                "inetAddressFamily": "IPV4",
                "ipaddrs": ipv4_addr,
                "mask": ipv4_len
            },
            "serialNumber": self.chassis_sn,
            "status": "Provisioned",
            "hostName": hostname,
            "message": "ZTP completed successfully"
        }
        result = rest_callback(f"{cnc_url}/crosswork/ztp/v1/deviceinfo/status", payload)
        if not succeeded(result):
            self.log_error(f"CNC notification failed: {result['output']}")

    def notify_cnc_failure(self, cnc_url):
        payload = {
            "serialNumber": self.chassis_sn,
            "status": "ProvisioningError",
            "message": "ZTP completed with errors"
        }
        result = rest_callback(f"{cnc_url}/crosswork/ztp/v1/deviceinfo/status", payload)
        if not succeeded(result):
            self.log_error(f"CNC notification failed: {result['output']}")


def parse_show_install(cmd_output):
    """
    Parse output of 'show install request'
    :param cmd_output: an iterable of lines (str) from the command output
    :return: (is_complete, is_success) tuple of bool. is_complete indicates whether the request completed,
            is_success indicates whether it was successful.
    """
    state_regex = re.compile(r'State\s*:\s*(.+?)\s*$')
    end_regex = re.compile(r'No install operation in progress')

    state = None
    is_complete = False
    for line in cmd_output:
        if state is None:
            state_match = state_regex.match(line)
            if state_match:
                state = state_match.group(1)
        elif end_regex.match(line):
            is_complete = True
            break

    return is_complete, state is not None and state.startswith('Success')


def parse_show_hwmodule(cmd_output):
    """
    Parse output of 'show hw-module fpd'
    :param cmd_output: an iterable of lines (str) from the command output
    :return: (is_complete, is_success) tuple of bool. is_complete indicates whether the request completed,
             is_success indicates whether it was successful.
    """
    line_regex = re.compile(
        r'\d+/\S+\s+(?P<fpd_line>.+)$'
    )

    is_complete = False
    num_matches = 0
    for cmd_line in cmd_output:
        match = line_regex.match(cmd_line)
        if match:
            num_matches += 1
            if 'UPGD PREP' in match.group('fpd_line'):
                break
    else:
        is_complete = True

    return is_complete, num_matches > 0


def parse_show_platform(desired_states, cmd_output):
    """
    Parse output of 'show platform'
    :param desired_states: Set of one or more LC state that is desired. That is, is_complete will return true
                           only if all LCs are in any of the desired states.
    :param cmd_output: an iterable of lines (str) from the command output
    :return: (is_complete, is_success) tuple of bool. is_complete indicates whether the request completed,
             is_success indicates whether it was successful.
    """
    line_regex = re.compile(
        r'(?P<node>\d+/\S+)'
        r'\s+(?P<lc>[a-zA-Z0-9\-]+)(?:\((?P<redundancy_state>[a-zA-Z]+)\))?(?:\s+(?P<plim>[a-zA-Z/]+))?'
        r'\s+(?P<state>(IOS XR RUN|OK|OPERATIONAL|FPD_UPGRADE|BOOTING|PLATFORM INITIALIZED|SHUTTING DOWN|CARD_ACCESS_DOWN|ONLINE|DATA PATH POWERED ON)+)'
        r'\s+(?P<config_state>[a-zA-Z,]+)$'
    )

    is_complete = False
    num_matches = 0
    for cmd_line in cmd_output:
        match = line_regex.match(cmd_line)
        if match:
            num_matches += 1
            if match.group('state') not in desired_states:
                break
    else:
        is_complete = True

    return is_complete, num_matches > 0


def succeeded(result, status_key='status', success_value='success'):
    return result.get(status_key, '') == success_value


def get_filename(download_result, folder_key='folder', filename_key='filename'):
    return os.path.join(download_result[folder_key], download_result[filename_key])


def rest_callback(url, payload=None, username=None, password=None, apikey=None, timeout=60):
    """
    Sends HTTP request to URL. If payload is provided, this will be a POST request; otherwise it is a GET request.
    If username/password are provided, HTTP basic authentication is used.
    :param url: String representing the URL target
    :param payload: (optional) Python object that can be encoded as json string.
    :param username: (optional) String
    :param password: (optional) String
    :param apikey: (optional) String
    :param timeout: (optional) Timeout value in seconds
    :return: dictionary with status and output { 'status': 'error/success', 'output': ''}
    """
    request = Request(url, json.dumps(payload).encode() if payload is not None else None,
                      {'Content-Type': 'application/json'})
    if username and password:
        base64str = base64.b64encode(f'{username}:{password}'.encode())
        request.add_header('Authorization', f'Basic {base64str}')
    elif apikey:
        request.add_header('apiKey', str(apikey))

    try:
        response = http_request(request, http_context(url), timeout)
    except ZTPErrorException as e:
        return {"status": "error", "output": str(e)}

    return {"status": "success", "output": str(response)}


class CncApi(object):
    MAX_RETRIES = 10
    SLEEP_SECS = 30

    def __init__(self, base_url, username=None, password=None, timeout=60, verify=False, ca_cert=None):
        self.base_url = base_url
        self.timeout = timeout
        self.ticket = None
        self.session_headers = {'Content-Type': 'application/json'}

        self.ctx = http_context(base_url, verify, ca_cert)

        if not self.login(username, password):
            raise ZTPErrorException(f'Login to {base_url} failed, check credentials')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()
        return False

    def login(self, username, password):
        ticket_body = {
            'username': username,
            'password': password
        }
        ticket_request = Request(f'{self.base_url}/crosswork/sso/v1/tickets',
                                 data=urlparser.urlencode(ticket_body).encode(),
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
        ticket = http_request(ticket_request, self.ctx, self.timeout).decode('utf-8')

        token_body = {
            'service': f'{self.base_url}/app-dashboard'
        }
        token_request = Request(f'{self.base_url}/crosswork/sso/v1/tickets/{ticket}',
                                data=urlparser.urlencode(token_body).encode(),
                                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        token = http_request(token_request, self.ctx, self.timeout).decode('utf-8')

        self.ticket = ticket
        self.session_headers['Authorization'] = f'Bearer {token}'

        return True

    def logout(self):
        if self.ticket is None or 'Authorization' not in self.session_headers:
            return

        request = Request(f'{self.base_url}/crosswork/sso/v1/tickets/{self.ticket}',
                          method='DELETE',
                          headers=self.session_headers)
        http_request(request, self.ctx, self.timeout).decode('utf-8')

    def get_node_uuid(self, serial_number):
        nodes_request = Request(f'{self.base_url}/crosswork/inventory/v1/nodes/query',
                                data=b'{}',
                                headers=self.session_headers)
        response = http_request(nodes_request, self.ctx, self.timeout).decode('utf-8')

        for entry in json.loads(response).get('data', []):
            if entry.get('serial_number', '') == serial_number:
                return entry.get('uuid')

        return None

    def get_cdg_vuuid(self, cdg_name=None):
        dg_request = Request(f'{self.base_url}/crosswork/dg-manager/v1/dg/query',
                             data=b'{}',
                             headers=self.session_headers)
        response = http_request(dg_request, self.ctx, self.timeout).decode('utf-8')

        for entry in json.loads(response).get('data', []):
            if entry.get('operationalData', {}).get('operState', '') != 'OS_UP':
                continue
            if cdg_name is None or entry.get('name', '') == cdg_name:
                return entry.get('configData', {}).get('vdgUuid')

        return None

    def set_node_cdg_map(self, node_uuid, cdg_vuuid):
        map_body = {
            "dgDeviceMappings": [
                {
                    "cdg_duuid": cdg_vuuid,
                    "mapping_oper": "ADD_OPER",
                    "device_uuid": [node_uuid]
                }
            ]
        }
        map_request = Request(f'{self.base_url}/crosswork/inventory/v1/dg/devicemapping',
                              data=json.dumps(map_body).encode(),
                              method='PUT',
                              headers=self.session_headers)
        map_response = http_request(map_request, self.ctx, self.timeout).decode('utf-8')

        state = json.loads(map_response).get('state', '')

        if state not in {'JOB_COMPLETED', 'JOB_ACCEPTED'}:
            raise ZTPErrorException(f'CDG map request failed: {state}')

        return

    def nso_sync_from(self, node_uuid):
        sync_from_body = {
            "filter": {"uuid": node_uuid}
        }
        sync_from_request = Request(f'{self.base_url}/crosswork/inventory/v1/nso/sync-from',
                                    data=json.dumps(sync_from_body).encode(),
                                    headers=self.session_headers)
        sync_from_response = http_request(sync_from_request, self.ctx, self.timeout).decode('utf-8')

        state = json.loads(sync_from_response).get('state', '')
        if state not in {'JOB_COMPLETED', 'JOB_ACCEPTED'}:
            raise ZTPErrorException(f'NSO sync-from request failed: {state}')

        return


def http_context(base_url, verify=False, ca_cert=None):
    ctx = None
    if urlparser.urlparse(base_url).scheme == 'https':
        if verify:
            if not ca_cert:
                raise ZTPErrorException("Invalid CA certificate")
            ctx = ssl.create_default_context(cafile=ca_cert)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    return ctx


def http_request(request_obj, context, timeout=60):
    try:
        with urlopen(request_obj, timeout=timeout, context=context) as f:
            return f.read()
    except HTTPError as e:
        raise ZTPErrorException(f"HTTP Code: {e.code}, {e.reason}")
    except URLError as e:
        raise ZTPErrorException(f"URL Error: {e.reason}")
    except socket.timeout:
        raise ZTPErrorException("HTTP request timeout")


class ZtpMetadata(object):
    def __init__(self, defaults=None, **kwargs):
        """
        :param kwargs: key-value pairs of metadata config
        """
        self._data = kwargs
        self.defaults = defaults or {}

    def __getattr__(self, item):
        attr = self._data.get(item, self.defaults.get(item, ...))
        if attr is ...:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{item}'")
        if isinstance(attr, str):
            return attr.strip()

        return attr

    @classmethod
    def load_file(cls, filename):
        try:
            with open(filename, 'r') as read_f:
                meta_data = json.load(read_f)

            if not isinstance(meta_data, dict):
                raise TypeError('Metadata file must be a dictionary')
        except (TypeError, ValueError) as e:
            raise ZTPErrorException(f'Invalid metadata file: {e}')
        else:
            return cls(**meta_data)


class ZTPErrorException(Exception):
    """ Exception ZTP errors, script will stop but still sys.exit(0) so no config rollback happens """
    pass


class ZTPCriticalException(Exception):
    """ Exception ZTP critical issues, script will stop and sys.exit(1). Any applied config will rollback """
    pass


if __name__ == "__main__":
    try:
        main()
    except ZTPErrorException as ex:
        logging.getLogger('ZTPLogger').error(ex)
        sys.exit(0)
    except ZTPCriticalException as ex:
        logging.getLogger('ZTPLogger').critical(ex)
        sys.exit(1)
    else:
        sys.exit(0)

# End
