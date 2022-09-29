<?php
/**
 * Classfile for WatchGuardService Object.
 *
 * @author       Werner Maier <wm@boc.de>
 * @copyright    (C) 2019 BOC IT-Security GmbH
 */
namespace BOC;

use SimpleXMLElement;

/**
 * Class WatchGuardService
 * @package BOC
 */
class WatchGuardService extends WatchGuardObject
{

    /**
     * WatchGuardService constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element) {
        parent::__construct($element);

        /**
         * all WatchGuard default services will be referenced automatically
         * this allows usage of "-u" or "--unused to show only unused
         * and thus deleteable services.
         */
        $defaultServices = array(
            "Allow Hotspot Session Mgmt",
            "Archie",
            "Auth",
            "BGP",
            "Citrix",
            "Clarent-Command",
            "Clarent-Gateway",
            "CU-SeeMe",
            "DHCP-Client",
            "DHCP-Server",
            "DNS",
            "DNS-proxy",
            "Entrust",
            "Explicit-proxy",
            "Finger",
            "FTP",
            "FTP-proxy",
            "Gopher",
            "GRE",
            "H323-ALG",
            "HBCI",
            "HTTP",
            "HTTP-proxy",
            "HTTPS",
            "HTTPS-proxy",
            "IDENT",
            "IGMP",
            "IKE",
            "IMAP",
            "IMAP-proxy",
            "Intel-Video-Phone",
            "IPSec",
            "IRC",
            "Kerberos-V4",
            "Kerberos-V5",
            "L2TP",
            "LDAP",
            "LDAP-SSL",
            "Lotus-Notes",
            "MS-SQL-Monitor",
            "MS-SQL-Server",
            "MS-Win-Media",
            "NetMeeting",
            "NFS",
            "NNTP",
            "NTP",
            "OSPF",
            "pcAnywhere",
            "PIM",
            "Ping",
            "POP2",
            "POP3",
            "POP3-proxy",
            "PPTP",
            "RADIUS",
            "RADIUS-Accounting",
            "RADIUS-Acct-RFC",
            "RADIUS-RFC",
            "RDP",
            "RealPlayerG2",
            "RIP",
            "RIPng",
            "Rlogin",
            "RSH",
            "SecurID",
            "SIP-ALG",
            "SMB",
            "SMTP",
            "SMTP-proxy",
            "SNMP",
            "SNMP-Trap",
            "SQL*Net",
            "SQL-Server",
            "SSH",
            "SSL-VPN",
            "SunRPC",
            "Syslog",
            "TACACS",
            "TACACS+",
            "TCP",
            "TCP-UDP",
            "TCP-UDP-proxy",
            "Telnet",
            "TFTP",
            "Timbuktu",
            "Time",
            "Traceroute",
            "UDP",
            "UUCP",
            "WAIS",
            "WG-Auth",
            "WG-Cert-Portal",
            "WG-Cloud-Managed-WiFi",
            "WG-Cloud-Managed-WiFi.1",
            "WG-Firebox-Mgmt",
            "WG-Fireware-XTM-WebUI",
            "WG-Gateway-Wireless-Controller",
            "WG-Logging",
            "WG-LogViewer-ReportMgr",
            "WG-Mgmt-Server",
            "WG-SmallOffice-Mgmt",
            "WG-TDR-Host-Sensor",
            "WG-WebBlocker",
            "WHOIS",
            "WinFrame",
            "X11",
        );

        if (in_array($element->{'name'},$defaultServices)) {
            // Services is WatchGuard default
            $this->storeReference("WatchGuard Default","service");
        }
    }

    /**
     * Returns the property element of $this
     * @return string
     */
    public function getProperty() {
        $object = $this->obj;
        return $object->property->__toString();
    }

}

