import os
import abc_os_manipulation
import common
from RoboGalaxyLibrary.utilitylib import exec_process as exec_proc
from robot.libraries import OperatingSystem
from robot.libraries import String
import iLo_utils

class Win_Manipulation(abc_os_manipulation.Abc_Os_Manipulation):
    def __init__(self, os, sys_ip, sys_password, host_name):
        self.__sys_os = os        
        self.__sys_ip = sys_ip
        self.__sys_password = sys_password
        self.__host_name = host_name

    def os(self):
        return self.__os
    
    def sys_ip(self):
        return self.__sys_ip

    def sys_password(self):
        return self.__sys_password

    def host_name(self):
        return self.__host_name
		
    def Set_iLO_Info(self, ip, password):
        self.__iLo_ip = ip
        self.__iLo_password = password
        
    def _Set_PSRemote_Execution_Policy(self):
        f = open(common.ps_script_path, 'w+')
        f.write("Enable-PSRemoting -Force" + '\n')
        f.write("Set-Item wsman:\\localhost\\client\\trustedhosts * -Force" + '\n')
        f.write("Restart-Service WinRM" + '\n')
        f.write("$secpwd = ConvertTo-SecureString " + self.__sys_password + " -AsplainText -Force" + '\n')
        f.write("$cred = New-Object System.Management.Automation.PSCredential ('Administrator', $secpwd)" + '\n')
        f.write("Invoke-Command -ComputerName " + self.__sys_ip + " -ScriptBlock { Set-ExecutionPolicy unrestricted -force} -Credential $cred" + '\n')
        f.close()
        
    def Get_Os_Version(self):
        f = open(common.ps_script_path, 'w+')
        f.write("$secpwd = ConvertTo-SecureString " + self.__sys_password + " -AsplainText -Force" + '\n')
        f.write("$cred = New-Object System.Management.Automation.PSCredential ('Administrator',$secpwd)" + '\n')
        f.write("(Get-WmiObject -comp " + self.__sys_ip + " -Credential $cred -class Win32_OperatingSystem ).Version" + '\n')
        f.close()
        
        cmd = "powershell.exe " + common.ps_script_path
        (stdout, stderr) = exec_proc.run_cmd(cmd)
        stdout = stdout.strip('\r\n')
        print stdout
        
        os_distro = self.Verify_Os_Version(stdout)
        
        # remove ps script
        cmd = "del " + common.ps_script_path
        exec_proc.run_cmd(cmd)
        
        return os_distro
        
    def Verify_Os_Version(self, value):
        if value == '6.0.6001':
            os_version = 'w2k8'
        elif value == '6.1.7600.16385' or value == '6.1.7601':
            os_version = 'w2k8r2'
        elif value == '6.2.9200': 
            os_version = 'w2k12'
        elif value == '6.3.9200' or value == '6.3.9600':
            os_version = 'w2k12r2'
        elif value == '10.0.14393':
            os_version = 'w2k16'
        else:
            os_version = 'Unsupport Version'
        return os_version
        
    def Install_Driver(self, driver_path, media_host, force ):
        #remove duplicate driver path in list
        driver_path = list(set(driver_path))
        for path in driver_path:
            print path
            file = os.path.basename(path)
            file_name = os.path.splitext(file)[0]
            media_path = media_host + path
            
            print file
            print file_name
            print media_path
            
            f = open(common.ps_script_path, 'w+')
            f.write("$url = \"" + media_path + "\"" + '\n')
            f.write("$output = \"C:\\" + file + "\"" + '\n')
            f.write("$start_time = Get-Date" + '\n')
            f.write("Invoke-WebRequest -Uri $url -OutFile $output" + '\n')
            f.write("Write-Output \"Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)\"" + '\n')
            f.close()
            
            cmd = "powershell.exe " + common.ps_script_path
            exec_proc.run_cmd(cmd)
            # remove ps script
            cmd = "del " + common.ps_script_path
            exec_proc.run_cmd(cmd)
            
            
            f = open(common.ps_script_path, 'w+')
            f.write("$dest = \"\\\\" + self.__sys_ip + "\\C$\"" + '\n')
            f.write("$pwd = ConvertTo-SecureString " + self.__sys_password + " -AsPlainText -Force" + '\n')
            f.write("$cred = new-object System.Management.Automation.PSCredential ('Administrator', $pwd)" + '\n')
            f.write("New-PSDrive -Name J -PSProvider FileSystem -Root $dest -Credential $cred" + '\n')
            f.write("Copy-Item -Path \"C:\\" + file + "\" -Destination \"J:\\\"" + '\n')
            f.close()
            
            cmd = "powershell.exe " + common.ps_script_path
            exec_proc.run_cmd(cmd)
            # remove ps script
            cmd = "del " + common.ps_script_path
            exec_proc.run_cmd(cmd)
            
            f = open(common.ps_script_path, 'w+')
            f.write("$secpwd = ConvertTo-SecureString '" + self.__sys_password + "' -AsplainText -Force" + '\n')
            f.write("$cred = New-Object System.Management.Automation.PSCredential ('Administrator',$secpwd)" + '\n')
            f.write("Invoke-Command -ComputerName '" + self.__host_name + "' -ScriptBlock { Start-Process -Wait -FilePath C:\\" + file + " -ArgumentList '/S','/f' } -Credential $cred" + '\n')
            f.close()
            
            cmd = "powershell.exe " + common.ps_script_path
            (stdout, stderr) = exec_proc.run_cmd(cmd)

            # remove ps script
            cmd = "powershell.exe " + common.ps_script_path
            exec_proc.run_cmd(cmd)
            
            stdout = common.PASS
        return stdout, file_name

    def Install_Firmware(self, fw_path, media_host, install_option):
        dir_path = common.fast_dir_root;
        
        power_shell_script_path = common.ps_script_path
        
        fw_path = list(set(fw_path)) #remove duplicate driver path in list
        
        for path in fw_path:
            file_name = os.path.basename(path)
            file_basename = os.path.splitext(file_name)[0]
            media_path = media_host + path
            
            # Copy a firmware component from media server to RG server
            power_shell_script_content = ('$url = \'%s\'\n' +
                                          '$output = \'C:\\%s\'\n' +
                                          '$start_time = Get-Date\n' +
                                          'Invoke-WebRequest -Uri $url -OutFile $output\n' +
                                          'Write-Output \'Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)\'') %(media_path, file_name)
            self._Create_PSScript(False)
            self._Append_PSScript(power_shell_script_content)
            self._Execute_PSScript()
            
            # Copy the firmware component from RG server to SUT
            power_shell_script_content = ('$dest = \'\\\\%s\\C$\'\n' +
                                          'New-PSDrive -Name J -PSProvider FileSystem -Root $dest -Credential $cred\n' +
                                          'Copy-Item -Path \'C:\\%s\' -Destination \'J:\\\'\n') %(self.__sys_ip, file_name)
            self._Create_PSScript()
            self._Append_PSScript(power_shell_script_content)
            self._Execute_PSScript()
            
            # Install firmware on SUT
            power_shell_script_content = ('Invoke-Command -ComputerName \'%s\' -ScriptBlock { Start-Process -Wait -FilePath C:\\%s -ArgumentList \'/S\',\'/f\' } -Credential $cred\n') %(self.__host_name, file_name)
            self._Create_PSScript()
            self._Append_PSScript(power_shell_script_content)
            stdout, stderr = self._Execute_PSScript()

            print ('stdout = %s' %stdout)
            print ('stderr = %s' %stderr)
            
            stdout = common.PASS
        return stdout, file_basename
        
    def Get_Sut_Driver_Version(self, nic_name):
        dict = {}
        for nic in nic_name:
            f = open(common.ps_script_path, 'w+')
            f.write("$secpwd = ConvertTo-SecureString " + self.__sys_password + " -AsplainText -Force" + '\n')
            f.write("$cred = New-Object System.Management.Automation.PSCredential ('Administrator',$secpwd)" + '\n')
            f.write("Invoke-Command -Computer " + self.__sys_ip + " -Scriptblock {" + '\n')
            f.write("ForEach ($Adapter in (Get-CimInstance Win32_NetworkAdapter)){" + '\n')
            f.write("$deviceid = $Adapter.PNPDeviceID" + '\n')
            f.write("$name = $Adapter.Name" + '\n')
            f.write("if($name -match \'" + nic + "\' ){" + '\n')
            f.write("$Info=Get-WMIObject Win32_PNPSignedDriver|Where-Object {$_.DeviceID -eq $deviceId}" + '\n')
            f.write("return $Info.driverversion}}} -Credential $cred" + '\n')
            
            f.close()
            
            cmd = "powershell.exe " + common.ps_script_path
            (stdout, stderr) = exec_proc.run_cmd(cmd)
            stdout = stdout.strip('\r\n')

            # remove ps script
            cmd = "del " + common.ps_script_path
            exec_proc.run_cmd(cmd)
            dict[nic] = stdout
            
        print dict
        return dict
            
    def Check_Connection(self):
        power_shell_script_content = ('$service = Get-Service -ComputerName \'%s\' -name winrm\n' +
                                      'while(($service.status) -ne \"Running\"){\n' +
                                      'start-sleep -s 5\n' +
                                      '$service = Get-Service -ComputerName \'%s\' -name winrm\n' +
                                      '$service.status}\n') %(self.__sys_ip, self.__sys_ip)
        print (power_shell_script_content)
        self._Create_PSScript(False)
        self._Append_PSScript(power_shell_script_content)

        cmd = "powershell.exe " + common.ps_script_path
        (stdout, stderr) = exec_proc.run_cmd(cmd)

        #if len(stdout) == 0 or 'fail' in stderr or 'error' in stderr:
        if 'fail' in stderr or 'error' in stderr:
            result = common.FAIL
        else:
            result = common.PASS
            
        return result
    
    def UnInstall_Driver(self, file_name):
        pnpdeviceid_list = self.Get_Nic_Pnpdeviceid()
        
        for deviceid in pnpdeviceid_list:
            f = open(common.ps_script_path, 'w+')
            f.write("$exe = \"C:\\PSTools\\psexec.exe\"" + '\n')
            f.write("&$exe \\\\" + self.__sys_ip + " -u Administrator -p " + self.__sys_password + " -c -f C:\\PSTools\\devcon /r remove \"@" + deviceid + "\"" + '\n')
            f.close()
            print deviceid
            
            cmd = "powershell.exe " + common.ps_script_path
            exec_proc.run_cmd(cmd)
            
        return common.PASS
            
        
    def Get_Nic_Pnpdeviceid(self):
        f = open(common.ps_script_path, 'w+')
        f.write("$secpwd = ConvertTo-SecureString " + self.__sys_password + " -AsplainText -Force" + '\n')
        f.write("$cred = New-Object System.Management.Automation.PSCredential ('Administrator',$secpwd)" + '\n')
        f.write("Invoke-Command -Computer " + self.__sys_ip + " -Scriptblock {" + '\n')
        f.write("ForEach ($Adapter in (Get-CimInstance Win32_NetworkAdapter)){" + '\n')
        f.write("$Config = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter \"Index = '$($Adapter.Index)'\"" + '\n')
        f.write("if(!$Config.IPAddress){" + '\n')
        f.write("$ipv4 = $Config.IPAddress}" + '\n')
        f.write("else{" + '\n')
        f.write("$ipv4 = $Config.IPAddress[0]}" + '\n')
        f.write("if($ipv4){" + '\n')
        f.write("if($ipv4 -notmatch " + self.__sys_ip + " ){" + '\n')
        f.write("$pnpdeviceid= $Adapter.PNPDeviceID + " " + $pnpdeviceid}" + '\n')
        f.write("else{" + '\n')
        f.write("$pnpdeviceid= $pnpdeviceid + $Adapter.PNPDeviceID + \" \"}}}" + '\n')
        f.write("return $pnpdeviceid} -credential $cred" + '\n')
        f.close()

        cmd = "powershell.exe " + common.ps_script_path
        (stdout, stderr) = exec_proc.run_cmd(cmd)

        pnpdeviceid_list = String.String().split_string(stdout)
        
        # remove ps script
        cmd = "del " + common.ps_script_path
        exec_proc.run_cmd(cmd)

        return pnpdeviceid_list
    
    def _Create_PSScript(self, remote_management = True):
        f = open(common.ps_script_path, 'w+')
        if remote_management: 
            f.write("$secpwd = ConvertTo-SecureString " + self.__sys_password + " -AsplainText -Force" + "\n")
            f.write("$cred = New-Object System.Management.Automation.PSCredential ('Administrator',$secpwd)" + "\n")
        f.close()
        
    def _Append_PSScript(self, command):
        f = open(common.ps_script_path, 'a')
        f.write(command + "\n")
        f.close()
        
    def _Execute_PSScript(self):
        stdout = None # stdout: output of cmd result
        stderr = None # stderr: error message. If the cmd executes successfully, stderr will be empty.
        try:
            cmd = "powershell.exe " + common.ps_script_path
            (stdout, stderr) = exec_proc.run_cmd(cmd)

            cmd = "del " + common.ps_script_path
            exec_proc.run_cmd(cmd)

        except Exception, e:
            print "Fail to Execute PSScript': " + str(e)

        finally:
            return stdout, stderr
    
    def Login_Check(self):
        self._Set_PSRemote_Execution_Policy()
        stdout, stderr = self._Execute_PSScript()

        if stderr:
            result = common.FAIL
        else:
            result = common.PASS
        
        return result

    def Package_Check(self, app_name):
        result = common.FAIL
        try:
            self._Create_PSScript()
            self._Append_PSScript("Invoke-Command -ComputerName " + self.__sys_ip + " -ScriptBlock { Get-WindowsFeature | Where-Object {$_.InstallState -match \"Installed\" -and $_.Name -match \"" + app_name + "\"} } -Credential $cred")
            stdout, stderr = self._Execute_PSScript()

            if len(stdout) == 0 or 'fail' in stderr or 'error' in stderr:
                result = common.FAIL
            else:
                result = common.PASS

        except Exception, e:
            print "Fail to check package '" + app_name + "': " + str(e)
        
        finally:
            return result

    def Third_Party_Tool_Check(self, tool_name):
        result = common.FAIL
        try:
            self._Create_PSScript()
            self._Append_PSScript("Invoke-Command -ComputerName " + self.__sys_ip + " -ScriptBlock { Get-ChildItem -Path C:\ -Name " + tool_name + " -Recurse | Select-Object -First 1 } -Credential $cred")
            stdout, stderr = self._Execute_PSScript()
            
            if len(stdout) == 0 or 'fail' in stderr or 'error' in stderr:
                result = common.FAIL
            else:
                result = common.PASS
        
        except Exception, e:
            print "Fail to check third party tool '" + tool_name + "': " + str(e)
        
        finally:
            return result

    def Shutdown_System():
        print ('do nothing')
    
    '''
    To install 7-zip on SUT
    Force install to dir C:\7-Zip
    '''
    def install_7zip(self, executable_file_path):
        print ('Install 7-Zip...')
        
        installation_dir = 'C:\\7-Zip'
        power_shell_script_content = 'Invoke-Command -ComputerName \'%s\' -ScriptBlock { Start-Process -Wait -FilePath %s -ArgumentList \'/S\',\'/D=%s\'} -Credential $cred\n' %(self.__sys_ip, executable_file_path, installation_dir)
        
        self._Create_PSScript()
        self._Append_PSScript(power_shell_script_content)
        stdout, stderr = self._Execute_PSScript()

        if len(stderr) > 0:
            print ('Failed to install 7-Zip.')
    
    '''
    To extract file from component package
    '''
    def extract_file(self, component_package_path, filename_wildcard):
        result = common.FAIL
        
        cmd_path = 'C:\\7-Zip\\7z.exe'
        cmd_name = os.path.basename(cmd_path)
        cmd_basename = os.path.splitext(cmd_name)[0]
        
        component_package_name = os.path.basename(component_package_path)
        component_package_basename = os.path.splitext(component_package_name)[0]
        destination_dir = 'C:\\%s' %(component_package_basename)

        # Check if 7-Zip is installed
        cmd_exist = self.Third_Party_Tool_Check (cmd_name)
        if cmd_exist is not common.PASS:
            self.install_7zip('C:\\7z1604-x64.exe')
        
        # Check if destination directory exists. If not, then create it.
        power_shell_script_content = 'Invoke-Command -ComputerName \'%s\' -ScriptBlock { Test-Path %s } -Credential $cred' %(self.__sys_ip, destination_dir)
        self._Create_PSScript()
        self._Append_PSScript(power_shell_script_content)
        stdout, stderr = self._Execute_PSScript()
        
        if len(stderr) == 0 and 'False' in stdout:
            stdout = '' # reset stdout
            stderr = '' # reset stderr
            power_shell_script_content = 'Invoke-Command -ComputerName \'%s\' -ScriptBlock { New-Item %s -type directory } -Credential $cred' %(self.__sys_ip, destination_dir)
            self._Create_PSScript()
            self._Append_PSScript(power_shell_script_content)
            stdout, stderr = self._Execute_PSScript()
        else:
            # If a bin file with the same name already exist, remove it. Otherwise, the extract process will be hanging. This is a workaround.
            power_shell_script_content = 'Invoke-Command -ComputerName \'%s\' -ScriptBlock { Remove-Item %s } -Credential $cred' %(self.__sys_ip, os.path.join(destination_dir, filename_wildcard))
            self._Create_PSScript()
            self._Append_PSScript(power_shell_script_content)
            stdout, stderr = self._Execute_PSScript()
        
        # Extract component from component package (cpxxxxxx.exe) with 7-Zip
        stdout = '' # reset stdout
        stderr = '' # reset stderr
        cmd_args = ['e ' + component_package_path, '-ir0!' + filename_wildcard, '-o' + destination_dir]
        start_process_cmd = self.generate_powershell_execute_cmd (cmd_path, cmd_args)
        power_shell_script_content = 'Invoke-Command -ComputerName \'%s\' -ScriptBlock {%s} -Credential $cred\n' %(self.__sys_ip, start_process_cmd)
        print (power_shell_script_content)
        
        self._Create_PSScript()
        self._Append_PSScript(power_shell_script_content)
        stdout, stderr = self._Execute_PSScript()

        if len(stderr) == 0:
            result = common.PASS
        
        return result
    
    def generate_powershell_execute_cmd (self, executable_file_path, arguments):
        start_process_cmd = '$process = Start-Process -Wait -FilePath \'%s\' -PassThru'
        
        start_process_cmd = start_process_cmd %(executable_file_path)
        
        argument_list = ''
        if len(arguments) > 0:
            start_process_cmd += ' -ArgumentList %s'
            
            for arg in arguments:
                argument_list += '\'%s\',' %arg
            
            argument_list = argument_list.rstrip(',')
            start_process_cmd = start_process_cmd %(argument_list)
        
        return start_process_cmd
