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

    private $serviceItems;
    private $servicePorts;
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
            "AOL",
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
            "TCP-proxy",
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
            "WG-Cloud-Managed-WiFi.2",
            "WG-Cloud-Managed-WiFi.3",
            "WG-Cloud-Managed-WiFi.4",
            "WG-Cloud-Managed-WiFi.5",
            "WG-Cloud-Managed-WiFi.6",
            "WG-Cloud-Managed-WiFi.7",
            "WG-Cloud-Managed-WiFi.8",
            "WG-Cloud-Managed-WiFi.9",
            "WG-Firebox-Mgmt",
            "WG-Fireware-XTM-WebUI",
            "WG-Gateway-Wireless-Controller",
            "WG-Logging",
            "WG-LogViewer-ReportMgr",
            "WG-LogViewer-ReportMgr.1",
            "WG-LogViewer-ReportMgr.2",
            "WG-LogViewer-ReportMgr.3",
            "WG-LogViewer-ReportMgr.4",
            "WG-LogViewer-ReportMgr.5",
            "WG-LogViewer-ReportMgr.6",
            "WG-LogViewer-ReportMgr.7",
            "WG-LogViewer-ReportMgr.8",
            "WG-LogViewer-ReportMgr.9",
            "WG-LogViewer-ReportMgr.10",
            "WG-LogViewer-ReportMgr.11",
            "WG-LogViewer-ReportMgr.12",
            "WG-LogViewer-ReportMgr.13",
            "WG-LogViewer-ReportMgr.14",
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

        foreach ($this->obj->{'service-item'}->children() as $member) {
            $this->serviceItems[] = $member;

            switch ($member->{'protocol'}->__toString()) {
                case "0":
                    $protocol = "Any";
                    break;
                case "1":
                    $protocol = "icmp";
                    break;
                case "2":
                    $protocol = "igmp";
                    break;
                case "58":
                    $protocol = "icmpv6";
                    break;
                case "6":
                    $protocol = "tcp";
                    break;
                case "17":
                    $protocol = "udp";
                    break;
                case "47":
                    $protocol = "gre";
                    break;
                case "50":
                    $protocol = "esp";
                    break;
                case "51":
                    $protocol = "ah";
                    break;
                case "89":
                    $protocol = "ospf";
                    break;
                case "103":
                    $protocol = "pim";
                    break;
                default:
                    $protocol = "???";
                    break;
            }

            switch ($member->{'type'}->__toString()) {
                case "1":
                    switch($protocol) {
                        case "icmp":
                        case "icmpv6":
                            $port = "type " . $member->{'icmp-type'}->__toString() . " " .
                                    "code " . $member->{'icmp-code'}->__toString();
                            break;
                        case "Any":
                        case "tcp":
                        case "udp":
                        case "gre":
                        case "igmp":
                        case "ospf":
                        case "pim":
                        case "esp":
                        case "ah":
                            $port = $member->{'server-port'}->__toString();
                            break;
                        default:
                            $port = "1??? " . json_encode($member);
                            break;
                    }
                    break;
                case "2":
                    switch($protocol) {
                        case "tcp":
                        case "udp":
                            $port = $member->{'start-server-port'}->__toString() . "-". $member->{'start-server-port'}->__toString();
                        break;
                        default:
                            $port = "2??? " . json_encode($member);
                    }
                    break;
                default:
                    $port = "3??? " . json_encode($member);
                    break;
            }

            $this->servicePorts[]="$port/$protocol";
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

    /**
     * detailed printout of service information
     * @param WatchGuardXMLFile $xmlfile
     */
    protected function verbosetextout($xmlfile)
    {
        global $options;

        if (isset($options['verbose'])) {
            parent::verbosetextout($xmlfile);
            $protocol = "???";

            print "  Ports:\n";
            foreach($this->servicePorts as $port) {
                print "    $port\n";
            }
        }

        print "\n";
    }

    /**
     * @return array
     */
    public function getServicePorts()
    {
        return $this->servicePorts;
    }

}

