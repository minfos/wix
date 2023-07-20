// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

namespace WixToolset.Firewall
{
    using System;
    using System.Collections.Generic;
    using System.Xml.Linq;
    using WixToolset.Data;
    using WixToolset.Data.WindowsInstaller;
    using WixToolset.Extensibility;

    /// <summary>
    /// The decompiler for the WiX Toolset Firewall Extension.
    /// </summary>
    public sealed class FirewallDecompiler : BaseWindowsInstallerDecompilerExtension
    {
        public override IReadOnlyCollection<TableDefinition> TableDefinitions => FirewallTableDefinitions.All;

        /// <summary>
        /// Called at the beginning of the decompilation of a database.
        /// </summary>
        /// <param name="tables">The collection of all tables.</param>
        public override void PreDecompileTables(TableIndexedCollection tables)
        {
        }

        /// <summary>
        /// Decompiles an extension table.
        /// </summary>
        /// <param name="table">The table to decompile.</param>
        public override bool TryDecompileTable(Table table)
        {
            switch (table.Name)
            {
                case "Wix4FirewallException":
                    this.DecompileWixFirewallExceptionTable(table);
                    break;
                default:
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Finalize decompilation.
        /// </summary>
        /// <param name="tables">The collection of all tables.</param>
        public override void PostDecompileTables(TableIndexedCollection tables)
        {
            this.FinalizeFirewallExceptionTable(tables);
        }

        /// <summary>
        /// Decompile the WixFirewallException table.
        /// </summary>
        /// <param name="table">The table to decompile.</param>
        private void DecompileWixFirewallExceptionTable(Table table)
        {
            foreach (Row row in table.Rows)
            {
                var firewallException = new XElement(FirewallConstants.FirewallExceptionName,
                    new XAttribute("Id", row.FieldAsString(0)),
                    new XAttribute("Name", row.FieldAsString(1))
                );

                string[] addresses = ((string)row[2]).Split(',');
                if (1 == addresses.Length)
                {
                    // special-case the Scope attribute values
                    if ("*" == addresses[0])
                    {
                        firewallException.Add(new XAttribute("Scope", "any"));
                    }
                    else if ("LocalSubnet" == addresses[0])
                    {
                        firewallException.Add(new XAttribute("Scope", "localSubnet"));
                    }
                    else
                    {
                        FirewallDecompiler.AddRemoteAddress(firewallException, addresses[0]);
                    }
                }
                else
                {
                    foreach (string address in addresses)
                    {
                        FirewallDecompiler.AddRemoteAddress(firewallException, address);
                    }
                }

                if (!row.IsColumnEmpty(3))
                {
                    firewallException.Add(new XAttribute("Port", row.FieldAsString(3)));
                }

                if (!row.IsColumnEmpty(4))
                {
                    switch (Convert.ToInt32(row[4]))
                    {
                        case FirewallConstants.NET_FW_IP_PROTOCOL_TCP:
                            firewallException.Add(new XAttribute("Protocol", "tcp"));
                            break;
                        case FirewallConstants.NET_FW_IP_PROTOCOL_UDP:
                            firewallException.Add(new XAttribute("Protocol", "udp"));
                            break;
                    }
                }

                if (!row.IsColumnEmpty(5))
                {
                    firewallException.Add(new XAttribute("Program", row.FieldAsString(5)));
                }

                if (!row.IsColumnEmpty(6))
                {
                    var attr = Convert.ToInt32(row[6]);
                    AttributeIfNotNull("IgnoreFailure", 0x1 == (attr & 0x1));

                    // default value is true
                    if (0x2 != (attr & 0x2))
                    {
                        AttributeIfNotNull("EdgeTraversal", false);
                    }
                }

                if (!row.IsColumnEmpty(7))
                {
                    switch (Convert.ToInt32(row[7]))
                    {
                        case FirewallConstants.NET_FW_PROFILE2_DOMAIN:
                            firewallException.Add(new XAttribute("Profile", "domain"));
                            break;
                        case FirewallConstants.NET_FW_PROFILE2_PRIVATE:
                            firewallException.Add(new XAttribute("Profile", "private"));
                            break;
                        case FirewallConstants.NET_FW_PROFILE2_PUBLIC:
                            firewallException.Add(new XAttribute("Profile", "public"));
                            break;
                        case FirewallConstants.NET_FW_PROFILE2_ALL:
                            firewallException.Add(new XAttribute("Profile", "all"));
                            break;
                    }
                }

                if (!row.IsColumnEmpty(9))
                {
                    firewallException.Add(new XAttribute("Description", row.FieldAsString(9)));
                }

                if (!row.IsColumnEmpty(10))
                {
                    switch (Convert.ToInt32(row[10]))
                    {
                        case FirewallConstants.NET_FW_RULE_DIR_IN:

                            firewallException.Add(AttributeIfNotNull("Outbound", false));
                            break;
                        case FirewallConstants.NET_FW_RULE_DIR_OUT:
                            firewallException.Add(AttributeIfNotNull("Outbound", true));
                            break;
                    }
                }

                // Introduced after 4.0.1
                if (row.Fields.Length > 11 && !row.IsColumnEmpty(11))
                {
                    firewallException.Add(new XAttribute("Service", row.FieldAsString(11)));
                }

                if (row.Fields.Length > 12 && !row.IsColumnEmpty(12))
                {
                    var interfaceTypes = row.FieldAsString(12);
                    var interfaceTypesValue = 0;
                    if ("All" == interfaceTypes)
                    {
                        interfaceTypesValue = Int32.MaxValue;
                    }
                    else
                    {
                        if (interfaceTypes.Contains("Wireless"))
                        {
                            interfaceTypesValue |= 0x1;
                        }

                        if (interfaceTypes.Contains("Lan"))
                        {
                            interfaceTypesValue |= 0x2;
                        }

                        if (interfaceTypes.Contains("RemoteAccess"))
                        {
                            interfaceTypesValue |= 0x4;
                        }
                    }

                    firewallException.Add(new XAttribute("InterfaceTypes", interfaceTypesValue));
                }

                this.DecompilerHelper.IndexElement(row, firewallException);
            }
        }

        private static void AddRemoteAddress(XElement firewallException, string address)
        {
            var remoteAddress = new XElement(FirewallConstants.RemoteAddressName,
                new XAttribute("Value", address)
            );

            firewallException.AddAfterSelf(remoteAddress);
        }

        private static XAttribute AttributeIfNotNull(string name, bool value)
        {
            return new XAttribute(name, value ? "yes" : "no");
        }

        /// <summary>
        /// Finalize the FirewallException table.
        /// </summary>
        /// <param name="tables">Collection of all tables.</param>
        private void FinalizeFirewallExceptionTable(TableIndexedCollection tables)
        {
            if (tables.TryGetTable("Wix4FirewallException", out var firewallExceptionTable))
            {
                foreach (var row in firewallExceptionTable.Rows)
                {
                    var xmlConfig = this.DecompilerHelper.GetIndexedElement(row);

                    var componentId = row.FieldAsString(8);
                    if (this.DecompilerHelper.TryGetIndexedElement("Component", componentId, out var component))
                    {
                        component.Add(xmlConfig);
                    }
                    else
                    {
                        this.Messaging.Write(WarningMessages.ExpectedForeignRow(row.SourceLineNumbers, firewallExceptionTable.Name, row.GetPrimaryKey(), "Component_", componentId, "Component"));
                    }
                }
            }
        }
    }
}
