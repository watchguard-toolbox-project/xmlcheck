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
            "Clarent-Command",
            "Clarent-Gateway",
            "CU-SeeMe",
            "DHCP-Client",
            "DHCP-Server",
            "DNS",
            "DNS-proxy",
            "Entrust",
            "Finger",
            "FTP",
            "FTP-proxy",
            "Gopher",
            "GRE",
            "HBCI",
            "HTTP",
            "HTTP-proxy",
            "HTTPS",
            "IDENT",
            "IGMP",
            "IKE",
            "IMAP",
            "Intel-Video-Phone",
            "IPSec",
            "IRC",
            "Kerberos-V4",
            "Kerberos-V5",
            "LDAP",
            "LDAP-SSL",
            "Lotus-Notes",
            "L2TP",
            "MS-SQL-Monitor",
            "MS-SQL-Server",
            "MS-Win-Media",
            "NetMeeting",
            "NFS",
            "NNTP",
            "NTP",
            "OSPF",
            "pcAnywhere",
            "Ping",
            "POP2",
            "POP3",
            "POP3-proxy",
            "PPTP",
            "RADIUS",
            "RADIUS-Accounting",
            "RADIUS-RFC",
            "RADIUS-Acct-RFC",
            "RealPlayerG2",
            "RDP",
            "Rlogin",
            "RIP",
            "RSH",
            "SecurID",
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
            "TCP-UDP-proxy",
            "TCP-UDP",
            "Telnet",
            "Time",
            "Timbuktu",
            "Traceroute",
            "UDP",
            "UUCP",
            "WAIS",
            "WG-Firebox-Mgmt",
            "WG-Fireware-XTM-WebUI",
            "WG-Auth",
            "WG-Mgmt-Server",
            "WG-Logging",
            "WG-SmallOffice-Mgmt",
            "WG-WebBlocker",
            "WHOIS",
            "WinFrame",
            "X11",
            "TFTP",
            "H323-ALG",
            "SIP-ALG",
            "HTTPS-proxy",
            "WG-LogViewer-ReportMgr",
            "WG-Gateway-Wireless-Controller",
            "RIPng",
            "Explicit-proxy",
            "WG-TDR-Host-Sensor",
            "PIM",
            "WG-Cloud-Managed-WiFi.1",
            "WG-Cert-Portal",
            "WG-Cloud-Managed-WiFi",
            "IMAP-proxy",
            "Archie",
            "Auth",
            "BGP",
            "Citrix",
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

