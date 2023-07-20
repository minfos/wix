// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

namespace WixToolset.Firewall
{
    using System;
    using System.Collections.Generic;
    using System.Xml.Linq;
    using WixToolset.Data;
    using WixToolset.Extensibility;
    using WixToolset.Extensibility.Data;
    using WixToolset.Firewall.Symbols;

    /// <summary>
    /// The compiler for the WiX Toolset Firewall Extension.
    /// </summary>
    public sealed class FirewallCompiler : BaseCompilerExtension
    {
        public override XNamespace Namespace => FirewallConstants.Namespace;

        /// <summary>
        /// Processes an element for the Compiler.
        /// </summary>
        /// <param name="sourceLineNumbers">Source line number for the parent element.</param>
        /// <param name="parentElement">Parent element of element to process.</param>
        /// <param name="element">Element to process.</param>
        /// <param name="contextValues">Extra information about the context in which this element is being parsed.</param>
        public override void ParseElement(Intermediate intermediate, IntermediateSection section, XElement parentElement, XElement element, IDictionary<string, string> context)
        {
            switch (parentElement.Name.LocalName)
            {
                case "File":
                    var fileId = context["FileId"];
                    var fileComponentId = context["ComponentId"];

                    switch (element.Name.LocalName)
                    {
                        case "FirewallException":
                            this.ParseFirewallExceptionElement(intermediate, section, parentElement, element, fileComponentId, fileId, null);
                            break;
                        default:
                            this.ParseHelper.UnexpectedElement(parentElement, element);
                            break;
                    }
                    break;
                case "Component":
                    var componentId = context["ComponentId"];

                    switch (element.Name.LocalName)
                    {
                        case "FirewallException":
                            this.ParseFirewallExceptionElement(intermediate, section, parentElement, element, componentId, null, null);
                            break;
                        default:
                            this.ParseHelper.UnexpectedElement(parentElement, element);
                            break;
                    }
                    break;
                case "ServiceConfig":
                    var serviceConfigName = context["ServiceConfigServiceName"];
                    var serviceConfigComponentId = context["ServiceConfigComponentId"];

                    switch (element.Name.LocalName)
                    {
                        case "FirewallException":
                            this.ParseFirewallExceptionElement(intermediate, section, parentElement, element, serviceConfigComponentId, null, serviceConfigName);
                            break;
                        default:
                            this.ParseHelper.UnexpectedElement(parentElement, element);
                            break;
                    }
                    break;
                case "ServiceInstall":
                    var serviceInstallName = context["ServiceInstallName"];
                    var serviceInstallComponentId = context["ServiceInstallComponentId"];

                    switch (element.Name.LocalName)
                    {
                        case "FirewallException":
                            this.ParseFirewallExceptionElement(intermediate, section, parentElement, element, serviceInstallComponentId, null, serviceInstallName);
                            break;
                        default:
                            this.ParseHelper.UnexpectedElement(parentElement, element);
                            break;
                    }
                    break;
                default:
                    this.ParseHelper.UnexpectedElement(parentElement, element);
                    break;
            }
        }

        /// <summary>
        /// Parses a FirewallException element.
        /// </summary>
        /// <param name="parentElement">The parent element of the one being parsed.</param>
        /// <param name="element">The element to parse.</param>
        /// <param name="componentId">Identifier of the component that owns this firewall exception.</param>
        /// <param name="fileId">The file identifier of the parent element (null if nested under Component).</param>
        /// <param name="serviceName">The service name of the parent element (null if not nested under ServiceConfig or ServiceInstall).</param>
        private void ParseFirewallExceptionElement(Intermediate intermediate, IntermediateSection section, XElement parentElement, XElement element, string componentId, string fileId, string serviceName)
        {
            var sourceLineNumbers = this.ParseHelper.GetSourceLineNumbers(element);
            Identifier id = null;
            string name = null;
            int attributes = 0x2; // set feaEdgeTraversal on by default
            string file = null;
            string program = null;
            string service = null;
            string port = null;
            int? protocol = null;
            int? profile = null;
            string scope = null;
            string remoteAddresses = null;
            string description = null;
            int? direction = null;
            string interfaceTypes = null;

            foreach (var attrib in element.Attributes())
            {
                if (String.IsNullOrEmpty(attrib.Name.NamespaceName) || this.Namespace == attrib.Name.Namespace)
                {
                    switch (attrib.Name.LocalName)
                    {
                        case "Id":
                            id = this.ParseHelper.GetAttributeIdentifier(sourceLineNumbers, attrib);
                            break;
                        case "Name":
                            name = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "File":
                            if (null != fileId)
                            {
                                this.Messaging.Write(ErrorMessages.IllegalAttributeWhenNested(sourceLineNumbers, element.Name.LocalName, "File", parentElement.Name.LocalName));
                            }
                            else
                            {
                                file = this.ParseHelper.GetAttributeIdentifierValue(sourceLineNumbers, attrib);
                            }
                            break;
                        case "IgnoreFailure":
                            if (YesNoType.Yes == this.ParseHelper.GetAttributeYesNoValue(sourceLineNumbers, attrib))
                            {
                                attributes |= 0x1; // feaIgnoreFailures
                            }
                            break;
                        case "EdgeTraversal":
                            if (YesNoType.No == this.ParseHelper.GetAttributeYesNoValue(sourceLineNumbers, attrib))
                            {
                                attributes &= ~0x2; // remove feaEdgeTraversal
                            }
                            break;
                        case "Program":
                            if (null != fileId)
                            {
                                this.Messaging.Write(ErrorMessages.IllegalAttributeWhenNested(sourceLineNumbers, element.Name.LocalName, "Program", parentElement.Name.LocalName));
                            }
                            else
                            {
                                program = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            }
                            break;
                        case "Service":
                            if (null != serviceName)
                            {
                                this.Messaging.Write(ErrorMessages.IllegalAttributeWhenNested(sourceLineNumbers, element.Name.LocalName, "Service", parentElement.Name.LocalName));
                            }
                            else
                            {
                                service = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            }
                            break;
                        case "Port":
                            port = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "Protocol":
                            var protocolValue = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            switch (protocolValue)
                            {
                                case "tcp":
                                    protocol = FirewallConstants.NET_FW_IP_PROTOCOL_TCP;
                                    break;
                                case "udp":
                                    protocol = FirewallConstants.NET_FW_IP_PROTOCOL_UDP;
                                    break;
                                default:
                                    this.Messaging.Write(ErrorMessages.IllegalAttributeValue(sourceLineNumbers, element.Name.LocalName, "Protocol", protocolValue, "tcp", "udp"));
                                    break;
                            }
                            break;
                        case "Scope":
                            scope = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            switch (scope)
                            {
                                case "any":
                                    remoteAddresses = "*";
                                    break;
                                case "localSubnet":
                                    remoteAddresses = "LocalSubnet";
                                    break;
                                default:
                                    this.Messaging.Write(ErrorMessages.IllegalAttributeValue(sourceLineNumbers, element.Name.LocalName, "Scope", scope, "any", "localSubnet"));
                                    break;
                            }
                            break;
                        case "InterfaceTypes":
                            this.ParseInterfaceTypesElement(element, attrib, ref interfaceTypes);
                            break;
                        case "Profile":
                            var profileValue = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            switch (profileValue)
                            {
                                case "domain":
                                    profile = FirewallConstants.NET_FW_PROFILE2_DOMAIN;
                                    break;
                                case "private":
                                    profile = FirewallConstants.NET_FW_PROFILE2_PRIVATE;
                                    break;
                                case "public":
                                    profile = FirewallConstants.NET_FW_PROFILE2_PUBLIC;
                                    break;
                                case "all":
                                    profile = FirewallConstants.NET_FW_PROFILE2_ALL;
                                    break;
                                default:
                                    this.Messaging.Write(ErrorMessages.IllegalAttributeValue(sourceLineNumbers, element.Name.LocalName, "Profile", profileValue, "domain", "private", "public", "all"));
                                    break;
                            }
                            break;
                        case "Description":
                            description = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "Outbound":
                            direction = this.ParseHelper.GetAttributeYesNoValue(sourceLineNumbers, attrib) == YesNoType.Yes
                                ? FirewallConstants.NET_FW_RULE_DIR_OUT
                                : FirewallConstants.NET_FW_RULE_DIR_IN;
                            break;
                        default:
                            this.ParseHelper.UnexpectedAttribute(element, attrib);
                            break;
                    }
                }
                else
                {
                    this.ParseHelper.ParseExtensionAttribute(this.Context.Extensions, intermediate, section, element, attrib);
                }
            }

            // parse RemoteAddress children
            foreach (var child in element.Elements())
            {
                if (this.Namespace == child.Name.Namespace)
                {
                    switch (child.Name.LocalName)
                    {
                        case "RemoteAddress":
                            if (null != scope)
                            {
                                this.Messaging.Write(FirewallErrors.IllegalRemoteAddressWithScopeAttribute(sourceLineNumbers));
                            }
                            else
                            {
                                this.ParseRemoteAddressElement(intermediate, section, child, ref remoteAddresses);
                            }
                            break;
                        default:
                            this.ParseHelper.UnexpectedElement(element, child);
                            break;
                    }
                }
                else
                {
                    this.ParseHelper.ParseExtensionElement(this.Context.Extensions, intermediate, section, element, child);
                }
            }

            if (null == id)
            {
                id = this.ParseHelper.CreateIdentifier("fex", name, remoteAddresses, componentId);
            }

            if (null == service)
            {
                service = serviceName;
            }

            // Name is required
            if (null == name)
            {
                this.Messaging.Write(ErrorMessages.ExpectedAttribute(sourceLineNumbers, element.Name.LocalName, "Name"));
            }

            // Scope or child RemoteAddress(es) are required
            if (null == remoteAddresses)
            {
                this.Messaging.Write(ErrorMessages.ExpectedAttributeOrElement(sourceLineNumbers, element.Name.LocalName, "Scope", "RemoteAddress"));
            }

            // can't have both Program and File
            if (null != program && null != file)
            {
                this.Messaging.Write(ErrorMessages.IllegalAttributeWithOtherAttribute(sourceLineNumbers, element.Name.LocalName, "File", "Program"));
            }

            // must be nested under File, have File or Program attributes, or have Port attribute
            if (String.IsNullOrEmpty(fileId) && String.IsNullOrEmpty(file) && String.IsNullOrEmpty(program) && String.IsNullOrEmpty(port))
            {
                this.Messaging.Write(FirewallErrors.NoExceptionSpecified(sourceLineNumbers));
            }

            if (!this.Messaging.EncounteredError)
            {
                // at this point, File attribute and File parent element are treated the same
                if (null != file)
                {
                    fileId = file;
                }

                var symbol = section.AddSymbol(new WixFirewallExceptionSymbol(sourceLineNumbers, id)
                {
                    Name = name,
                    RemoteAddresses = remoteAddresses,
                    Profile = profile ?? FirewallConstants.NET_FW_PROFILE2_ALL,
                    ComponentRef = componentId,
                    Description = description,
                    Direction = direction ?? FirewallConstants.NET_FW_RULE_DIR_IN,
                    Service = service,
                    InterfaceTypes = interfaceTypes,
                });

                if (!String.IsNullOrEmpty(port))
                {
                    symbol.Port = port;

                    if (!protocol.HasValue)
                    {
                        // default protocol is "TCP"
                        protocol = FirewallConstants.NET_FW_IP_PROTOCOL_TCP;
                    }
                }

                if (protocol.HasValue)
                {
                    symbol.Protocol = protocol.Value;
                }

                if (!String.IsNullOrEmpty(fileId))
                {
                    symbol.Program = $"[#{fileId}]";
                    this.ParseHelper.CreateSimpleReference(section, sourceLineNumbers, SymbolDefinitions.File, fileId);
                }
                else if (!String.IsNullOrEmpty(program))
                {
                    symbol.Program = program;
                }

                if (CompilerConstants.IntegerNotSet != attributes)
                {
                    symbol.Attributes = attributes;
                }

                this.ParseHelper.CreateCustomActionReference(sourceLineNumbers, section, "Wix4SchedFirewallExceptionsInstall", this.Context.Platform, CustomActionPlatforms.ARM64 | CustomActionPlatforms.X64 | CustomActionPlatforms.X86);
                this.ParseHelper.CreateCustomActionReference(sourceLineNumbers, section, "Wix4SchedFirewallExceptionsUninstall", this.Context.Platform, CustomActionPlatforms.ARM64 | CustomActionPlatforms.X64 | CustomActionPlatforms.X86);
            }
        }

        /// <summary>
        /// Parses an InterfaceTypes element
        /// </summary>
        /// <param name="element">The element to parse.</param>
        /// <param name="attribute">The attribute to parse.</param>
        private void ParseInterfaceTypesElement(XElement element, XAttribute attribute, ref string interfaceTypes)
        {
            var sourceLineNumbers = this.ParseHelper.GetSourceLineNumbers(element);
            var interfaceTypeValue = this.ParseHelper.GetAttributeIntegerValue(sourceLineNumbers, attribute, 0, Int32.MaxValue);

            if (Int32.MaxValue == interfaceTypeValue)
            {
                interfaceTypes = "All";
            }
            else
            {
                if (0x1 == (interfaceTypeValue & 0x1))
                {
                    interfaceTypes = "Wireless";
                }

                if (0x2 == (interfaceTypeValue & 0x2))
                {
                    if (String.IsNullOrEmpty(interfaceTypes))
                    {
                        interfaceTypes = "Lan";
                    }
                    else
                    {
                        interfaceTypes = String.Concat(interfaceTypes, ",", "Lan");
                    }
                }

                if (0x4 == (interfaceTypeValue & 0x4))
                {
                    if (String.IsNullOrEmpty(interfaceTypes))
                    {
                        interfaceTypes = "RemoteAccess";
                    }
                    else
                    {
                        interfaceTypes = String.Concat(interfaceTypes, ",", "RemoteAccess");
                    }
                }
            }
        }

        /// <summary>
        /// Parses a RemoteAddress element
        /// </summary>
        /// <param name="element">The element to parse.</param>
        private void ParseRemoteAddressElement(Intermediate intermediate, IntermediateSection section, XElement element, ref string remoteAddresses)
        {
            var sourceLineNumbers = this.ParseHelper.GetSourceLineNumbers(element);
            string address = null;

            // no attributes
            foreach (var attrib in element.Attributes())
            {
                if (String.IsNullOrEmpty(attrib.Name.NamespaceName) || this.Namespace == attrib.Name.Namespace)
                {
                    switch (attrib.Name.LocalName)
                    {
                        case "Value":
                            address = this.ParseHelper.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                    }
                }
                else
                {
                    this.ParseHelper.ParseExtensionAttribute(this.Context.Extensions, intermediate, section, element, attrib);
                }
            }

            this.ParseHelper.ParseForExtensionElements(this.Context.Extensions, intermediate, section, element);

            if (String.IsNullOrEmpty(address))
            {
                this.Messaging.Write(ErrorMessages.ExpectedAttribute(sourceLineNumbers, element.Name.LocalName, "Value"));
            }
            else
            {
                if (String.IsNullOrEmpty(remoteAddresses))
                {
                    remoteAddresses = address;
                }
                else
                {
                    remoteAddresses = String.Concat(remoteAddresses, ",", address);
                }
            }
        }
    }
}
