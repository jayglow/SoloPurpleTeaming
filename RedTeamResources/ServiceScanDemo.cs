using System;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Management;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Security;

namespace ServiceScanDemo
{
    internal class Program
    {
        [Flags]
        private enum AccessRights : uint
        {
            SC_MANAGER_CONNECT = 0x00000001,
            SC_MANAGER_ENUMERATE_SERVICE = 0x00000004,
            READ_CONTROL = 0x0020000
        }

        [Flags]
        enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        }


        // CloseServiceHandle
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenSCManager(
          string lpMachineName,
          string lpDatabaseName,
          uint dwDesiredAccess
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenService(
          IntPtr hSCManager,
          string lpServiceName,
          uint dwDesiredAccess
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceObjectSecurity(
            IntPtr hService,
            uint dwSecurityInformation,
            IntPtr lpSecurityDescriptor,
            uint cbBufSize,
            out uint pcbBytesNeeded
        );

        private const uint SDDL_REVISION_1 = 1;
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr SecurityDescriptor,
            uint RequestedStringSDRevision,
            uint SecurityInformation,
            out StringBuilder StringSecurityDescriptor,
            out uint StringSecurityDescriptorLen
        );

        public static string GetServiceSDDL(string serviceName)
        {
            // open connection to the SCM using OpenSCManager Win API call that lives advapi32.dll
            IntPtr scmHandle = OpenSCManager(null, null, (uint)(AccessRights.SC_MANAGER_ENUMERATE_SERVICE | AccessRights.SC_MANAGER_CONNECT));
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception($"Failed to connect to SCM. ERROR: {Marshal.GetLastWin32Error()}");
            }

            // Get handle to service using OpenService Win API call that lives in advapi32.dll
            IntPtr serviceHandle = IntPtr.Zero;
            IntPtr sdPtr = IntPtr.Zero;
            StringBuilder sddlStringBuilder = null;
            try
            {
                serviceHandle = OpenService(scmHandle, serviceName, (uint)AccessRights.READ_CONTROL);
                // Query the service object for the security descriptor and copy into memory
                // Query serviceHandle object for security descriptor using QueryServiceObjectSecurity
                uint bytesNeeded = 0;
                QueryServiceObjectSecurity(serviceHandle, (uint)(SECURITY_INFORMATION.DACL_SECURITY_INFORMATION | SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION), IntPtr.Zero, 0, out bytesNeeded);
                sdPtr = Marshal.AllocHGlobal((int)bytesNeeded);

                QueryServiceObjectSecurity(serviceHandle, (uint)(SECURITY_INFORMATION.DACL_SECURITY_INFORMATION | SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION), sdPtr, bytesNeeded, out bytesNeeded);

                // Convert the security descriptor to string and return
                // Get Security Descriptor

                uint sddlStringLen = 0;
                ConvertSecurityDescriptorToStringSecurityDescriptor(
                    sdPtr,
                    SDDL_REVISION_1,
                    (uint)(SECURITY_INFORMATION.DACL_SECURITY_INFORMATION | SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION),
                    out sddlStringBuilder,
                    out sddlStringLen
                    );

            }
            catch
            {
                int error = Marshal.GetLastWin32Error();
                if (error != 5)
                {
                    throw new Exception($"Could not get handle to service. ERROR: {error}");
                }
                else
                {
                    Console.WriteLine($"Access Denied to service {serviceName}");
                    return null;
                }
            }
            finally
            {
                // Clean UP
                if (sdPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(sdPtr);
                }
                if (serviceHandle != IntPtr.Zero)
                {
                    CloseServiceHandle(serviceHandle);
                }
                if (scmHandle != IntPtr.Zero)
                {
                    CloseServiceHandle(scmHandle);
                }
            }
            if (sddlStringBuilder != null)
            {
                return sddlStringBuilder.ToString();
            }
            else
            {
                return null;
            }

        }

        public static bool CanStartService(string sddl)
        {
            if (sddl != null)
            {
                WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                RawSecurityDescriptor rsd = new RawSecurityDescriptor(sddl);
                foreach (CommonAce ace in rsd.DiscretionaryAcl)
                {
                    if (ace.AceType == AceType.AccessAllowed)
                    {
                        if (currentUser.User == ace.SecurityIdentifier || currentUser.Groups.Contains(ace.SecurityIdentifier))
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        public static string GetServiceBinaryPath(string serviceName)
        {
            string path = null;
            string query = $"SELECT PathName FROM Win32_Service WHERE Name = '{serviceName}'";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection results = searcher.Get();
            foreach (ManagementObject result in results)
            {
                path = result["PathName"]?.ToString();
            }
            return path;
        }

        public static bool CanModifyServiceBinary(string pathName)
        {
            try
            {
                FileInfo fileInfo = new FileInfo(pathName);
                if (fileInfo.Exists)
                {
                    FileSecurity dacl = fileInfo.GetAccessControl();
                    WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                    AuthorizationRuleCollection aces = dacl.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    foreach(FileSystemAccessRule ace in aces)
                    {
                        var sid = (SecurityIdentifier)ace.IdentityReference.Translate(typeof(SecurityIdentifier));
                        if(currentUser.User != null && sid == currentUser.User)
                        {
                            if((ace.FileSystemRights & FileSystemRights.WriteData) == FileSystemRights.WriteData 
                                   && ace.AccessControlType == AccessControlType.Allow) {
                                return true;
                            }
                            if (currentUser.Groups.Contains(sid))
                            {
                                if ((ace.FileSystemRights & FileSystemRights.WriteData) == FileSystemRights.WriteData
                                   && ace.AccessControlType == AccessControlType.Allow)
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return false;
            }

            return false;
        }

        static void Main(string[] args)
        {
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                string sddl = GetServiceSDDL(service.ServiceName);
                if (CanStartService(sddl))
                {
                    
                    if (CanModifyServiceBinary(GetServiceBinaryPath(service.ServiceName))){
                        Console.WriteLine($"Display Name: {service.DisplayName}");
                        Console.WriteLine($"Start Type: {service.StartType}");
                        Console.WriteLine($"Status: {service.Status}");
                        Console.WriteLine($"Service Name: {service.ServiceName}");
                        Console.WriteLine(sddl);
                        Console.WriteLine("Can Start Service!");
                        Console.WriteLine("Can Modify Service Binary");
                        Console.WriteLine();
                    }
                }
            }
        }
    }
}
