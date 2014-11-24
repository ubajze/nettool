from Exscript import Account
from Exscript.util.interact import read_login
from Exscript.protocols import SSH2
from Exscript.protocols.drivers import ios

import sys
import os
import keyring
import datetime
import argparse
import ConfigParser
import getpass

class ExceptionTemplate(Exception):
    def __init__(self,msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class ConnectionError(ExceptionTemplate): pass
class AuthenticationError(ExceptionTemplate): pass
class CommandError(ExceptionTemplate): pass
class UserDoesNotExist(ExceptionTemplate): pass
class NoUsernameFound(ExceptionTemplate): pass
class NoPasswordFound(ExceptionTemplate): pass
class NoPathProvided(ExceptionTemplate): pass
class ConfigSyntaxError(ExceptionTemplate): pass

msg_unable_to_connect = 'Unable to connect to the host %s.'
msg_authentication_failed = 'Authentication failed.'
msg_command_failed = 'Command execution failed.'
user_does_not_exists_msg = 'User does not exist.'
no_username_found_msg = 'The username is not set.'
no_password_found_msg = 'The password is not set.'
no_path_provided_msg = 'Path is not provided.'
config_syntax_error_msg = 'There is a syntax error in the config file.'



class Credentials:

    def __init__(self):
        self.username = None
        self.password = None
   

    def set_credentials(self,username,password):
        self.username = username
        self.password = password

    def save_credentials(self):
        if self.username == None:
            raise NoUsernameFound(no_username_found_msg)
        elif self.password == None:
            raise NoPasswordFound(no_password_found_msg)
        else:
            keyring.set_password('system',username,password)
        return self.username,self.password

    @classmethod
    def get_password(cls,username):
        username = username
        password = keyring.get_password('system',username)
        if password == None:
            raise UserDoesNotExist(user_does_not_exists_msg)
        return password

class HostConnection:

    def __init__(self,host):
        self.host = host
        self.account = None
        self.account1 = None

    def login_account(self, username = None, password = None):
        self.account = Account(username,password)
        return self.account

    def enable_account(self,enable_username = None, enable_password = None):
        self.account1 = Account(enable_username, enable_password)
        return self.account1

    def connect_to_device_ios(self):
        self.conn = SSH2()
        self.conn.set_driver('ios')
        try:
            self.conn.connect(self.host)
        except:
            raise ConnectionError(msg_unable_to_connect %self.host)
        try:
            self.conn.authenticate(self.account)
            if self.account1:
                self.conn.auto_app_authorize(self.account1)
        except:
            raise AuthenticationError(msg_authentication_failed)
        self.conn.execute('terminal length 0')

    def execute_command(self,command):
        try:
            self.conn.execute(command)
            command_response = self.conn.response
            position = command_response.find('Translating')
            if position != -1:
                raise CommandError(msg_command_failed)
            return command_response
        except:
            raise CommandError(msg_command_failed)

    def disconnect_from_device(self):
        self.conn.send('\exit\r')
        self.conn.close()


class IosServices:

    def __init__(self, host, username = None, password = None, enable_username = None, enable_password = None):
        self.host = host
        self.username = username
        self.password = password
        self.enable_username = enable_username
        self.enable_password = enable_password
        self.connection = None

    def connect_to_device(self):
        self.connection = HostConnection(self.host)
        self.connection.login_account(self.username,self.password)
        if self.enable_password:
            self.connection.enable_account(self.enable_username,self.enable_password)
        self.connection.connect_to_device_ios()
        return self.connection

    def disconnect_from_device(self):
        self.connection.disconnect_from_device()


    def execute_multiple_commands(self,command_list):
        response_list = []
        for command in command_list:
            response = self.connection.execute_command(command)
            response_list.append(response)
        return response_list

    def save_string_to_file_system(self,string,path):
        f = open(path,'w')
        f.write(string)
        f.close

    def get_running_config(self,save_to_file_system = False,path = None):
        command_list = ['show running-config']
        response_list = self.execute_multiple_commands(command_list)
        if save_to_file_system:
            if not path:
                raise NoPathProvided(no_path_provided_msg)
            self.save_string_to_file_system(response_list[0],path)
        return response_list[0]

    def get_startup_config(self,save_to_file_system = False,path = None):
        command_list = ['show startup-config']
        response_list = self.execute_multiple_commands(command_list)
        if save_to_file_system:
           if not path:
               raise NoPathProvided(no_path_provided_msg)
           self.save_string_to_file_system(response_list[0],path)       
        return response_list[0]

    def save_configuration(self):
        command_list = ['write']
        response_list = self.execute_multiple_commands(command_list)
        return response_list[0]



if __name__ == "__main__":

    ## Inital values
    device_types = ['ios', 'asa']

    config_parameters = {
        'username': '',
        'password': '',
        'enable_username': '',
        'enable_password': '',
        'keyring': False,
        'type': device_types[0],
        'archive_location': '.',
        'save_running_config': False,
        'get_running_config': False,
        'running_config_prefix': 'run_&h_&d',
        'get_startup_config': False,
        'startup_config_prefix': 'start_&h_&d',
        'custom_cmd': None,
    }
    

    def parse_config(config_class):

        default_config = {}
        for key in config_parameters.keys():
            if config_class.has_option('default',key):
                default_config[key] = config_class.get('default', key)
            else:
                default_config[key] = config_parameters[key]


        host_list = []
        sections = config_class.sections()
        for section in sections:
            if section.split(' ')[0] == 'host':
                host = {}
                if config_class.has_option(section,'hostname'):
                    host['hostname'] = config_class.get(section,'hostname')
                else:
                    raise ConfigSyntaxError(config_syntax_error_msg)
                if config_class.has_option(section,'group'):
                    host_group = config_class.get(section,'group')
                else:
                    raise ConfigSyntaxError(config_syntax_error_msg)
                for key in config_parameters.keys():
                    if config_class.has_option(section,key):
                        host[key] = config_class.get(section,key)
                    elif config_class.has_option('group ' + host_group,key):
                        host[key] = config_class.get('group ' + host_group,key)
                    else:
                        host[key] = default_config[key]
                host_list.append(host)
        return host_list

    def get_filename(filename, host = ''):
        current_date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        filename_len = len(filename)
        new_filename = filename
        variables = ['&d','&h']

        for var in variables:
            position = filename.find(var)
            if var == '&d':
                padding = current_date
            elif var == '&h':
                padding = host
            if position != -1:
                new_filename = filename[0:position] + padding
                if position+2 != filename_len:
                    new_filename = new_filename + filename[position+2:]
            filename = new_filename

        return new_filename

    def get_file_path(path,filename):
        if os.path.isdir(path):
            file_path = path + "/" + filename
            return file_path
        else:
            error_msg = "The %s does not exist." %host_data['archive_location']
            print_log(error_msg)
            return False

    def get_custom_commands(custom_cmd_var):
        try:
            custom_commands_list = custom_cmd_var.split(':')
            command = []
            prefix = []
            for element in custom_commands_list:
                command.append(element[1:-1].split(',')[0])
                prefix.append(element[1:-1].split(',')[1])
            return command,prefix
        except:
            error_msg = "Parsing custom_cmd variable failed."
            print_log(error_msg)

    def print_log(msg,host = ''):
        current_date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        log_msg = current_date + ' ' + host + ' ' + msg
        print log_msg
        

    parser = argparse.ArgumentParser(prog='./nettool',description='Device management tool.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-config', metavar='config', help='Provide path to config file.')
    group.add_argument('-host', metavar='host', help='The IP or hostname of the device.')
    parser.add_argument('-user', metavar='username', help='The username for the device.')
    parser.add_argument('-pass', metavar='password', help='The password for the device.')
    parser.add_argument('-euser', metavar='username', help='The enable username for the device. (default: %s)' %config_parameters['enable_username'])
    parser.add_argument('-epass', metavar='password', help='The enable password for the device.')
    parser.add_argument('-type', metavar='type', help='The device type. (choices: %s, default: %s)' %(device_types, config_parameters['type']), choices=device_types)
    parser.add_argument('-path', metavar='path', help='The archive path. (default: %s)' %config_parameters['archive_location'])
    parser.add_argument('-save', action = 'store_true', help='Save running-config to startup-config. (default %s)' %config_parameters['save_running_config'])
    parser.add_argument('-run', action = 'store_true', help='Save the running config. (default: %s)' %config_parameters['get_running_config'])
    parser.add_argument('-run_file', metavar='filename', help='The name of the file. (default: %s)' %config_parameters['running_config_prefix'])
    parser.add_argument('-start', action = 'store_true', help='Save the startup config. (default: %s)' %config_parameters['get_startup_config'])
    parser.add_argument('-start_file', metavar='filename', help='The name of the file. (default: %s)' %config_parameters['startup_config_prefix'])
    parser.add_argument('-keyring', action = 'store_true' , help='Use keyring to get passwords. (default: %s)' %config_parameters['keyring'])
    parser.add_argument('-cmd', metavar='command_list' , help='Execute custom commands. (default: %s)' %config_parameters['custom_cmd'])


    args = vars(parser.parse_args())

    if not args['config']:
        config_parameters['hostname'] = args['host']
        if args['user']:
            config_parameters['username'] = args['user']
        else:
            config_parameters['username'] = raw_input('Username: ')
        if args['pass']:
            config_parameters['password'] = args['pass']
        else:
            if args['keyring']:
                try:
                    config_parameters['password'] = Credentials.get_password(config_parameters['username'])
                except UserDoesNotExist as err:
                    print_log(str(err), config_parameters['hostname'])
                    #print str(err) + ' Host: %s.' %config_parameters['hostname']
            else:
                config_parameters['password'] = getpass.getpass()
        if args['euser']:
            config_parameters['enable_username'] = args['euser']
        else:
            config_parameters['enable_username'] = raw_input('Enable username: ')
        if args['epass']:
            config_parameters['enable_password'] = args['epass']
        else:
            if args['keyring']:
                config_parameters['enable_password'] = Credentials.get_password(config_parameters['enable_username'])
            else:
                config_parameters['enable_password'] = getpass.getpass('Enable password: ')
        if args['type']:
            config_parameters['type'] = args['type']
        if args['path']:
            config_parameters['archive_location'] = args['path']
        if args['save']:
            config_parameters['save_running_config'] = args['save']
        if args['run']:
            config_parameters['get_running_config'] = args['run']
        if args['run_file']:
            config_parameters['running_config_prefix'] = args['run_file']
        if args['start']:
            config_parameters['get_startup_config'] = args['start']
        if args['start_file']:
            config_parameters['startup_config_prefix'] = args['start_file']
        if args['cmd']:
            config_parameters['custom_cmd'] = args['cmd']
        hosts = [config_parameters]


    else:
        config_location = args['config']
        del args['config']
        exit_program = False
        for key in args.keys():
            if args[key]:
                error_msg = "Argument %s is not allowed in config submode." %key
                print_log(error_msg)
                exit_program = True
        if exit_program:
            sys.exit(0)

        config = ConfigParser.ConfigParser()
        config.read(config_location)
        hosts = parse_config(config)

        for host in hosts:
            if host['keyring']:
                try:
                    host['password'] = Credentials.get_password(host['username'])
                    host['enable_password'] = Credentials.get_password(host['enable_username'])
                except UserDoesNotExist as err:
                    print_log(str(err),host['hostname'])

    for host in hosts:
        host_service = IosServices(host['hostname'],host['username'],host['password'],host['enable_username'],host['enable_password'])
        try:
            host_service.connect_to_device()
        except ConnectionError as err:
            print_log(str(err),host['hostname'])
            continue
        except AuthenticationError as err:
            print_log(str(err),host['hostname'])
            continue
        if host['save_running_config']:
            if config_parameters['type'] == 'ios':
                try:
                    host_service.save_configuration()
                    error_msg = "The running-config on the host %s was successfully saved to startup-config." %host['hostname']
                    print_log(error_msg,host['hostname'])
                except CommandError as err:
                    error_msg = str(err) + ' Operation: %s.' %'Save running config'
                    print_log(error_msg,host['hostname'])
        if host['get_running_config']:
            file_path = get_file_path(host['archive_location'],get_filename(host['running_config_prefix'],host['hostname']))
            if file_path:
                if config_parameters['type'] == 'ios':
                    try:
                        host_service.get_running_config(save_to_file_system=True, path = file_path)
                        error_msg = "Running-config for host %s was successfully saved to the %s." %(host['hostname'],file_path)
                        print_log(error_msg,host['hostname'])
                    except CommandError as err:
                        error_msg = str(err) + ' Operation: %s.' %'Get running config'
                        print_log(error_msg,host['hostname'])
        if host['get_startup_config']:
            file_path = get_file_path(host['archive_location'],get_filename(host['startup_config_prefix'],host['hostname']))
            if file_path:
                if config_parameters['type'] == 'ios':
                    try:
                        host_service.get_startup_config(save_to_file_system=True, path = file_path)
                        error_msg = "Startup-config for host %s was successfully saved to the %s." %(host['hostname'],file_path)
                        print_log(error_msg,host['hostname'])
                    except CommandError as err:
                        error_msg = str(err) + ' Operation: %s.' %'Get startup config'
                        print_log(error_msg,host['hostname'])
        if host['custom_cmd']:
            commands,prefixes = get_custom_commands(host['custom_cmd'])
            try:
                command_outputs = host_service.execute_multiple_commands(commands)
            except CommandError as err:
                error_msg = str(err) + ' Operation: %s.' %'Custom command'
                print_log(error_msg,host['hostname']) 
            try:
                for output in command_outputs:
                    current_postion = command_outputs.index(output)
                    file_path = get_file_path(host['archive_location'],get_filename(prefixes[current_postion]))
                    host_service.save_string_to_file_system(output, file_path)
                    error_msg = "Output of the command '%s' was successfully saved to the %s." %(commands[current_postion],file_path)
                    print_log(error_msg,host['hostname'])
            except:
                error_msg = "Saving outputs of the custom commands to file system failed."
                print_log(error_msg,host['hostname'])

    

        host_service.disconnect_from_device()



    


