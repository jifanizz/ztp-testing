#!/usr/bin/python

import sys
sys.path.append("/pkg/bin/")
import urllib2
import os, subprocess, shutil
from ztp_helper import ZtpHelpers
import re, datetime, json, tempfile, time
from time import gmtime, strftime

SW_VERSION = "7.7.2"
SW_NAME = "C8000-7.7.2"
SW_UUID = "cw-image-uuid-8fa4065f-048a-4220-97ff-3cecc19d8796"
CONFIG_FILE = "3a2ccb6f-400c-4186-b1cf-11a96eafc94b"
XRZTP_INTERFACE_NAME = "MgmtEth0/RP0/CPU0/0"
ROOT_USER = "admin"
ROOT_USER_CREDENTIALS = "$6$N8waO/0jdKPe3O/.$oYCFbNgtzrtBzz2O4Jp2K.9x3CaQLmBX/WE3C3NJay0EQJa6kWPB3pnpCdHvUJPZeJdpavzDTDXvGsV.ogKWS0" 
SERVER_URL = "http://198.18.201.25:30604/crosswork/"
SERVER_URL_PACKAGES = SERVER_URL+"imagesvc/v1/device/files/"
SERVER_URL_CONFIGS = SERVER_URL+"configsvc/v1/configs/device/files/"
SERVER_URL_API = SERVER_URL+"ztp/v1/deviceinfo/status"
SYSLOG_SERVER = "198.18.201.11"
SYSLOG_PORT = 514
SYSLOG_LOCAL_FILE = "/root/ztp_python.log"


NODE_TYPE = ["Line Card",
             "LC",
             "Route Processor",
             "Route Switch Processor"]

class ZtpFunctions(ZtpHelpers):

    def set_root_user(self):
        """User defined method in Child Class
           Sets the root user for IOS-XR during ZTP
           Leverages xrapply() method in ZtpHelpers Class.
           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': 'output from xrapply' }
           :rtype: dict
        """
        config = """ !
                     username %s 
                     group root-lr
                     group cisco-support
                     secret 10 %s 
                     !
                     end""" % (ROOT_USER, ROOT_USER_CREDENTIALS)

        with tempfile.NamedTemporaryFile(delete=True) as f:
            f.write("%s" % config)
            f.flush()
            f.seek(0)
            result = self.xrapply(f.name)

        if result["status"] == "error":

            self.syslogger.info("Failed to apply root user to system %s"+json.dumps(result))

        return result


    def all_nodes_ready(self):
        """ Method to check if all nodes on the chassis are ready 
            :return: Dictionary specifying success/error and an associated message
                     {'status': 'success/error',
                      'output':  True/False in case of success, 
                                 error mesage in case of error}
            :rtype: dict
        """

        show_inventory = self.xrcmd({"exec_cmd" : "show inventory | e PORT | i NAME:"})
        node_dict = {}

        if show_inventory["status"] == "success":
            try:
                for line in show_inventory["output"]:
                    if not any(tag in line for tag in ["NAME", "DESCR"]):
                        continue
                    str = '{'+line+'}'
                    str=str.replace("NAME", "\"NAME\"")
                    str=str.replace("DESCR", "\"DESCR\"")
                    if any(type in json.loads(str)['DESCR'] for type in NODE_TYPE):
                        node_dict[(json.loads(str)['NAME'])] = "inactive"
                        if self.debug:
                            self.logger.debug("Fetched Node inventory for the system")
                            self.logger.debug(node_dict)
            except Exception as e:
                if self.debug:
                    self.logger.debug("Error while fetching the node list from inventory")
                    self.logger.debug(e)
                return {"status": "error", "output": e }


            show_platform = self.xrcmd({"exec_cmd" : "show platform"})

            if show_platform["status"] == "success":
                try:
                    for node in node_dict:
                        for line in show_platform["output"]:
                            if node+'/CPU' in line.split()[0]:
                                node_state =  line.split()
                                xr_state = ' '.join(node_state[2:])
                                if 'IOS XR RUN' in xr_state:
                                    node_dict[node] = "active"
                except Exception as e:
                    if self.debug:
                        self.logger.debug("Error while fetching the XR status on node")
                        self.logger.debug(e)
                    return {"status": "error", "output": e }

            else:
                if self.debug:
                    self.logger.debug("Failed to get the output of show platform")
                return {"status": "error", "output": "Failed to get the output of show platform"}

        else:
            if self.debug:
                self.logger.debug("Failed to get the output of show inventory")
            return {"status": "error", "output": "Failed to get the output of show inventory"}


        if self.debug:
            self.logger.debug("Updated the IOS-XR state of each node")
            self.logger.debug(node_dict)

        if all(state == "active" for state in node_dict.values()):
            return {"status" : "success", "output": True}
        else:
            return {"status" : "success", "output": False}



    def wait_for_nodes(self, duration=600):
        """User defined method in Child Class
           Waits for all the linecards and RPs (detected in inventory)
           to be up before returning True.
           If 'duration' is exceeded, returns False.
 
           Use this method to wait for the system to be ready
           before installing packages or applying configuration.
           :param duration: Duration for which the script must
                            wait for nodes to be up.
                            Default Value is 600 seconds. 
           :type duration: int
           :return: Returns a True or False  
           :rtype: bool 
        """
        nodes_up = False
        t_end = time.time() + duration 
        while time.time() < t_end:
            nodes_check = self.all_nodes_ready()

            if nodes_check["status"] == "success":
                if nodes_check["output"]:
                    nodes_up = True
                else:
                    nodes_up = False

            else:
                self.syslogger.info("Failed to check if nodes are up, bailing out")
                self.syslogger.info(nodes_check["output"])

            if nodes_up:
                self.syslogger.info("All nodes up")
                return nodes_up
            else:
                self.syslogger.info("All nodes are not up")
                time.sleep(10)

        if not nodes_up:
            self.syslogger.info("All nodes did not come up, exiting")
            return nodes_up

    def xrreplace(self, filename=None):
        """Replace XR Configuration using a file 
          
           :param file: Filepath for a config file
                        with the following structure: 
                        !
                        XR config commands
                        !
                        end
           :type filename: str
           :return: Dictionary specifying the effect of the config change
                     { 'status' : 'error/success', 'output': 'exec command based on status'}
                     In case of Error:  'output' = 'show configuration failed' 
                     In case of Success: 'output' = 'show configuration commit changes last 1'
           :rtype: dict 
        """


        if filename is None:
            return {"status" : "error", "output": "No config file provided for xrreplace"}

        status = "success"

        try:
            if self.debug:
                with open(filename, 'r') as config_file:
                    data=config_file.read()
                self.logger.debug("Config File content to be applied %s" % data)
                
        except:
            return {"status" : "error" , "output" : "Invalid config file provided"}

        cmd = "source /pkg/bin/ztp_helper.sh && xrreplace " + filename

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

        # Check if the commit failed

        if process.returncode:
            ## Config commit failed.
            status = "error"
            exec_cmd = "show configuration failed"
            config_failed = self.xrcmd({"exec_cmd": exec_cmd})
            if config_failed["status"] == "error":
                output = "Failed to fetch config failed output"
            else:
                output = config_failed["output"]

            if self.debug:
                self.logger.debug("Config replace through file failed, output = %s" % output)
            return  {"status": status, "output": output}
        else:
            ## Config commit successful. Let's return the last config change
            exec_cmd = "show configuration commit changes last 1"
            config_change = self.xrcmd({"exec_cmd": exec_cmd})
            if config_change["status"] == "error":
                output = "Failed to fetch last config change"
            else:
                output = config_change["output"]

            if self.debug:
                self.logger.debug("Config replace through file successful, last change = %s" % output)
            return {"status": status, "output" : output}

    def chassis_sn(self):
        """User defined method in Child Class
                Fetches Chassis Serial number
                Leverages xrcmd() method in ZtpHelpers Class.
                :return: Return a dictionary with status and output
                            { 'output': 'output from xrcmd', 'warning' : 'Failed to discover chassis Serial Number' }
                :rtype: dict
                """
        try:
            result = {"output" : "", "warning" : ""}
            temp=[]
            show_inventory = self.xrcmd({"exec_cmd": "show inventory"})
            show_inven_iter = iter(show_inventory["output"])
            for line in show_inven_iter:
                if "Rack 0" in line:
                    temp = next(show_inven_iter).split()
                    break
            temp_len = len(temp)
            result["output"] = temp[temp_len-1]
            self.syslogger.info("ZTP LOG - Chassis SN is %s" % result["output"])

        except Exception:
                self.syslogger.info("ZTP LOG - Error while getting the chassis SN of router")
                result["warning"] = "Failed to discover chassis Serial Number"

        return result
    
    def get_config(self):
        """User defined method in Child Class
                Downloads initial device configuration usinf device SN
                Leverages urllib2 method.
                """
        try:
            request = urllib2.Request(SERVER_URL_CONFIGS + CONFIG_FILE)
            request.add_header('X-cisco-serial*', str(serial_number["output"]))
            responce = urllib2.urlopen(request)

            datatowrite = responce.read()
            with open('/disk0:/ztp/customer/downloaded-config', 'wb') as f:
                f.write(datatowrite)
            self.syslogger.info("ZTP Log - Initial device configuration downloaded")
        
        except Exception:
                self.syslogger.info("ZTP LOG - Error while getting the configuration file")


if __name__ == "__main__":

    # Create an Object of the child class, syslog parameters are optional. 
    # If nothing is specified, then logging will happen to local log rotated file.

    ztp_script = ZtpFunctions(syslog_file=SYSLOG_LOCAL_FILE, syslog_server=SYSLOG_SERVER, syslog_port=SYSLOG_PORT)
    ztp_script.syslogger.info("###### Starting ZTP RUN on NCS540 ######")

    # Enable verbose debugging to stdout/console. By default it is off
    ztp_script.toggle_debug(1)

    # No Config applied yet, so start with global-vrf(default)"
    #ztp_script.set_vrf("global-vrf")

    # Set the root user first. Always preferable so that the user can manually gain access to the router in case ZTP script aborts.
    ztp_script.set_root_user()

    # Let's wait for inventory manager to be updated before checking if nodes are ready
    time.sleep(120)

    # Wait for all nodes (linecards, standby etc.)  to be up before installing packages
    # Check for a user defined maximum (time in seconds)
    if ztp_script.wait_for_nodes(600):
        ztp_script.syslogger.info("All Nodes are up!") 
    else:
        ztp_script.syslogger.info("Nodes did not come up! Continuing")
        sys.exit(1)

    # We've waited and checked long enough
    # Install crypto keys
    show_pubkey = ztp_script.xrcmd({"exec_cmd" : "show crypto key mypubkey rsa"})

    if show_pubkey["status"] == "success":
        if show_pubkey["output"] == '':
            ztp_script.syslogger.info("No RSA keys present, Creating...")
            ztp_script.xrcmd({"exec_cmd" : "crypto key generate rsa", "prompt_response" : "2048\\n"})
        else:
            ztp_script.syslogger.info("RSA keys already present, no need to create....")
    else:
        ztp_script.syslogger.info("Unable to get the status of RSA keys: "+str(show_pubkey["output"]))
        # Not quitting the script because of this failure

    #Get chassis SN for use in config download
    ztp_script.syslogger.info("Fetching device serial number")
    serial_number = ztp_script.chassis_sn()

    #Download Initial device configuration
    ztp_script.syslogger.info("Downloading configration file")
    ztp_script.get_config()

    # Replace existing config with downloaded config file
    ztp_script.syslogger.info("Replacing system config with the downloaded config") 
    config_apply = ztp_script.xrreplace("/disk0:/ztp/customer/downloaded-config")

    if config_apply["status"] == "error":
        ztp_script.syslogger.info("Failed to replace existing config")
        ztp_script.syslogger.info("Config Apply result = %s" % config_apply["output"])
        STATUS = "ProvisioningError"
        MESSAGE = "Error encountered applying configuration file, ZTP process failed"
        try:
            os.remove("/disk0:/ztp/customer/downloaded-config" + CONFIG_FILE)
        except OSError:
            ztp_script.syslogger.info("Failed to remove downloaded config file")
    else :
        STATUS = "Provisioned"
        MESSAGE = "Applying system configuration complete, ZTP process completed"

    # Let's wait for configuration to be active before moving on
    time.sleep(120)

    # VRFs on Mgmt interface are configured by user. Use the set_vrf helper method to set proper
    # context before continuing. 
    # Syslog and download operations are covered by the set vrf utility by default.
    # For any other shell commands that utilize the network, 
    # change context to vrf using `ip netns exec <vrf>` before the command

    #ztp_script.set_vrf("Mgmt-intf")
    #ztp_script.syslogger.info("###### Changed context to user specified VRF based on config ######")
    #ztp_script.syslogger.info("Base config applied successfully")
    #ztp_script.syslogger.info("Config Apply result = %s" % config_apply["output"])

    # Update regitration with COE
    # Get management interface IP and subnet mask
    temp = []
    show_interfaces = ztp_script.xrcmd({"exec_cmd" : "show run interface "+ XRZTP_INTERFACE_NAME +" | i ipv4 address"})
    MgmtIP = str(show_interfaces["output"]).split()[2]
    mask = 24

    # get device hostname
    temp = []
    show_host = ztp_script.xrcmd({"exec_cmd" : "show running-config hostname"})
    temp = str(show_host["output"]).strip("[']")
    Hostname = temp.split()[1]

    # Update device status in COE

    data = json.dumps({
                "ipAddress":{
                         "inetAddressFamily": "IPV4",
                         "ipaddrs": str(MgmtIP),
                         "mask":  int(mask)
                     },
                     "serialNumber": str(serial_number["output"]), 
                     "status": str(STATUS), 
                     "hostName": str(Hostname),
                     "message": str(MESSAGE)
        })

    request = urllib2.Request(SERVER_URL_API, data)
    request.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(request)

    json_response = json.loads(response.read())
    if str(json_response["message"]) != "Device Updated Successfully":
        ztp_script.syslogger.info("Failed to notify ZTP completion to server, will try again. ZTP failed...")
        print("Failed to notify ZTP completion to server, will try again. ZTP failed..."+str(json_response))
        sys.exit(1)
    else :
        ztp_script.syslogger.info("Successfully notified server. ZTP complete.")

    ztp_script.syslogger.info("ZTP complete!")
    sys.exit(0)
