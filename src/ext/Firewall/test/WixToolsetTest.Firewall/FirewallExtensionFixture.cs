// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

namespace WixToolsetTest.Firewall
{
    using System.Linq;
    using WixInternal.TestSupport;
    using WixInternal.Core.TestPackage;
    using WixToolset.Firewall;
    using Xunit;
    using System.IO;
    using System.Xml.Linq;

    public class FirewallExtensionFixture
    {
        [Fact]
        public void CanBuildUsingFirewall()
        {
            var folder = TestData.Get(@"TestData\UsingFirewall");
            var build = new Builder(folder, typeof(FirewallExtensionFactory), new[] { folder });

            var results = build.BuildAndQuery(Build, "Wix4FirewallException", "CustomAction");
            WixAssert.CompareLineByLine(new[]
            {
                "CustomAction:Wix4ExecFirewallExceptionsInstall_X86\t3073\tWix4FWCA_X86\tExecFirewallExceptions\t",
                "CustomAction:Wix4ExecFirewallExceptionsUninstall_X86\t3073\tWix4FWCA_X86\tExecFirewallExceptions\t",
                "CustomAction:Wix4RollbackFirewallExceptionsInstall_X86\t3329\tWix4FWCA_X86\tExecFirewallExceptions\t",
                "CustomAction:Wix4RollbackFirewallExceptionsUninstall_X86\t3329\tWix4FWCA_X86\tExecFirewallExceptions\t",
                "CustomAction:Wix4SchedFirewallExceptionsInstall_X86\t1\tWix4FWCA_X86\tSchedFirewallExceptionsInstall\t",
                "CustomAction:Wix4SchedFirewallExceptionsUninstall_X86\t1\tWix4FWCA_X86\tSchedFirewallExceptionsUninstall\t",
                "Wix4FirewallException:ExampleFirewall\tExampleApp\t*\t42\t6\t[#filNdJBJmq3UCUIwmXS8x21aAsvqzk]\t2\t2147483647\tfilNdJBJmq3UCUIwmXS8x21aAsvqzk\tAn app-based firewall exception\t1\t\tAll",
                "Wix4FirewallException:fex70IVsYNnbwiHQrEepmdTPKH8XYs\tExamplePort\tLocalSubnet\t42\t6\t\t3\t2147483647\tfilNdJBJmq3UCUIwmXS8x21aAsvqzk\tA port-based firewall exception\t2\tftpsrv\tLan",
                "Wix4FirewallException:ServiceInstall.nested\tExamplePort\tLocalSubnet\t3546-7890\t6\t\t1\t2147483647\tfilNdJBJmq3UCUIwmXS8x21aAsvqzk\tA port-based firewall exception for a windows service\t1\tsvc1\tWireless,Lan,RemoteAccess",
            }, results);
        }

        [Fact]
        public void CanBuildUsingFirewallARM64()
        {
            var folder = TestData.Get(@"TestData\UsingFirewall");
            var build = new Builder(folder, typeof(FirewallExtensionFactory), new[] { folder });

            var results = build.BuildAndQuery(BuildARM64, "Wix4FirewallException", "CustomAction");
            WixAssert.CompareLineByLine(new[]
            {
                "CustomAction:Wix4ExecFirewallExceptionsInstall_A64\t3073\tWix4FWCA_A64\tExecFirewallExceptions\t",
                "CustomAction:Wix4ExecFirewallExceptionsUninstall_A64\t3073\tWix4FWCA_A64\tExecFirewallExceptions\t",
                "CustomAction:Wix4RollbackFirewallExceptionsInstall_A64\t3329\tWix4FWCA_A64\tExecFirewallExceptions\t",
                "CustomAction:Wix4RollbackFirewallExceptionsUninstall_A64\t3329\tWix4FWCA_A64\tExecFirewallExceptions\t",
                "CustomAction:Wix4SchedFirewallExceptionsInstall_A64\t1\tWix4FWCA_A64\tSchedFirewallExceptionsInstall\t",
                "CustomAction:Wix4SchedFirewallExceptionsUninstall_A64\t1\tWix4FWCA_A64\tSchedFirewallExceptionsUninstall\t",
                "Wix4FirewallException:ExampleFirewall\tExampleApp\t*\t42\t6\t[#filNdJBJmq3UCUIwmXS8x21aAsvqzk]\t2\t2147483647\tfilNdJBJmq3UCUIwmXS8x21aAsvqzk\tAn app-based firewall exception\t1\t\tAll",
                "Wix4FirewallException:fex70IVsYNnbwiHQrEepmdTPKH8XYs\tExamplePort\tLocalSubnet\t42\t6\t\t3\t2147483647\tfilNdJBJmq3UCUIwmXS8x21aAsvqzk\tA port-based firewall exception\t2\tftpsrv\tLan",
                "Wix4FirewallException:ServiceInstall.nested\tExamplePort\tLocalSubnet\t3546-7890\t6\t\t1\t2147483647\tfilNdJBJmq3UCUIwmXS8x21aAsvqzk\tA port-based firewall exception for a windows service\t1\tsvc1\tWireless,Lan,RemoteAccess",
            }, results);
        }

        [Fact]
        public void CanRoundtripFirewallExceptions()
        {
            var folder = TestData.Get(@"TestData", "UsingFirewall");
            var build = new Builder(folder, typeof(FirewallExtensionFactory), new[] { folder });
            var output = Path.Combine(folder, "FirewallExceptionDecompile.xml");

            build.BuildAndDecompileAndBuild(Build, Decompile, output);

            var doc = XDocument.Load(output);
            var firewallElementNames = doc.Descendants().Where(e => e.Name.Namespace == "http://minfos.com.au/schemas/v4/wxs/firewall")
                                      .Select(e => e.Name.LocalName)
                                      .ToArray();

            WixAssert.CompareLineByLine(new[]
            {
                "FirewallException",
                "FirewallException",
                "FirewallException",
            }, firewallElementNames);
        }


        private static void Build(string[] args)
        {
            var result = WixRunner.Execute(args);
            result.AssertSuccess();
        }

        private static void BuildARM64(string[] args)
        {
            var newArgs = args.ToList();
            newArgs.Add("-platform");
            newArgs.Add("arm64");

            var result = WixRunner.Execute(newArgs.ToArray());
            result.AssertSuccess();
        }
        private static void Decompile(string[] args)
        {
            var result = WixRunner.Execute(args);
            result.AssertSuccess();
        }
    }
}
