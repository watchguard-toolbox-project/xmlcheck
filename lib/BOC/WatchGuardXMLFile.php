<?php
/**
 * this contains the base class file
 *
 * here go methods for loading xmlfile and initaliyng all objects,
 * as well as crosschecking and printing loops.
 *
 * @author Werner Maier (wm@boc.de)
 * @copyright 2019 BOC IT-Security GmbH, www.boc.de
 */

/**
 * dummy
 */
namespace BOC;

// use BOC\WatchGuardAlias;
use BOC\WatchGuardObject;
use SimpleXMLElement;

/**
 * Class WatchGuardXMLFile
 * @package BOC
 */
class WatchGuardXMLFile
{
    /**
     * base object containing the loaded xml structure and all methods
     * @var SimpleXMLElement
     */
    private $xmlfile;       // complete xml structure as SimpleXML object

    // arrays for all aliases, policies and services:
    /**
     * array for all aliases from this xmlfile
     * @var array
     */
    private $allAliases;
    /**
     * array for all policies from this xmlfile
     * @var array
     */
    private $allPolicies;
    /**
     * array for all tunnels from this xmlfile
     * @var array
     */
    private $allTunnels;
    /**
     * array for filter-type
     * @var array
     */
    private $policyTypeFilter;
    /**
     * array for filter-tag
     * @var array
     */
    private $policyTagFilter;
    /**
     * array for filter-exclude-type
     * @var array
     */
    private $policyExcludeTypeFilter;
    /**
     * array for filter-port
     * @var array
     */
    private $typePortFilter;
    /**
     * array for filter-from
     * @var array
     */
    private $policyFromFilter;
    /**
     * array for filter-to
     * @var array
     */
    private $policyToFilter;
    /**
     * string for filter-action (deny/allow)
     * @var string
     */
    private $policyActionFilter;
    /**
     * array for all services from this xmlfile
     * @var array
     */
    private $allServices;

    /**
     * array for all tags from this xmlfile
     * @var array
     */
    private $allTags;

    /**
     * WatchGuardXMLFile constructor.
     *
     * loads the xmlfile, initializes all aliases, policies and services.
     *
     * @param $xmlfilename
     */
    public function __construct($xmlfilename) {
        $this->xmlfile = simplexml_load_file($xmlfilename);
        $this->allAliases  = [];
        $this->allPolicies = [];
        $this->allServices = [];
        $this->allTunnels = [];
        $this->allTags = [];

        // initialize filters as arrays
        // don't initialize policyActionFilter as it is no array.
        $this->policyFromFilter = [];
        $this->policyToFilter = [];
        $this->policyTypeFilter = [];
        $this->policyTagFilter = [];

        $this->policyExcludeTypeFilter = [];

        // initialize aliases, services and tags
        $this->getAllAliases();
        $this->getAllServices();
        $this->getAllTags();
        $this->getAllTunnels();

        // initialize policies (gets also references to tags and aliases)
        $this->getAllPolicies();

        // now find aliases in aliases
        $this->findAliasReferences();
        $this->findServiceRefByPolicy();
        $this->findTagRefByPolicy();
    }

    /**
     * reads all aliases from xml and sets the pointer into allAliases array
     **/
    private function getAllAliases() {

        foreach ($this->xmlfile->{'alias-list'}->children() as $alias) {
            $this->allAliases[$alias->name->__toString()] = new WatchGuardAlias($alias);
        }

    }

    /**
     * reads all tunnels from xml and sets the pointer into allTunels array
     **/
    private function getAllTunnels() {
        foreach ($this->xmlfile->{'ike-policy-group-list'}->children() as $tunnel) {
            $tunnelName = $tunnel->name->__toString();
            $this->allTunnels[$tunnelName] = new WatchGuardTunnel($tunnel);
        }
        foreach ($this->xmlfile->{'abs-ipsec-action-list'}->children() as $ipsecaction) {
            $ikepolicy=$ipsecaction->{'ike-policy'}->__toString();
            foreach ($ipsecaction->{'local-remote-pair-list'}->children() as $pair) {
                $this->allTunnels[$ikepolicy]->addTunnelRoute($pair);
            }
        }
    }

    /**
     * reads all tags from xml and sets the pointer into allTags array
     **/
    private function getAllTags() {

        foreach ($this->xmlfile->{'policy-tag-list'}->children() as $tag) {
            $this->allTags[$tag->name->__toString()] = new WatchGuardTag($tag);
        }

    }

    /**
     * reads all policies from xml and sets the pointer into allPolicies array
     *
     * also initializes the alias references; if an alias is referenced by this policy,
     * it is stored at the alias object.
     */
    private function getAllPolicies() {

        foreach ($this->xmlfile->{'policy-list'}->{'policy'} as $policy) {
            $policyName = $policy->name->__toString();
            $this->allPolicies[$policyName] = new WatchGuardPolicy($policy);
            $this->allPolicies[$policyName]->getReferencedAliases();
        }

    }

    /**
     * reads all services from xml and sets the pointer into allServices array
     */
    private function getAllServices() {

        foreach ($this->xmlfile->{'service-list'}->children() as $service) {
            $this->allServices[$service->name->__toString()] = new WatchGuardService($service);
        }

    }

    /**
     * searchs an xml object by name and returns the found simpleXMLElement
     *
     * @param SimpleXMLElement $obj
     * @param $searchname
     * @return SimpleXMLElement|null
     */
    private function getXMLObject(SimpleXMLElement $obj, $searchname) {
        $retval = null;

        foreach ($obj->children() as $child) {

            $name = $child->getName();
            if ($name != $searchname) continue;
            $retval = $child;
        }
        return $retval;
    }

    /**
     * resolves aliases for printing out the details
     *
     * currently supports addresses and networks (addr/mask).
     * and partly things like interfaces.
     *
     * @param $searchstring
     * @return string
     */
    public function resolveAliasAddress($searchstring)
    {

        $retval="";
        $addressGroup = $this->xmlfile->{'address-group-list'}->{'address-group'};

        foreach ($addressGroup as $addgroupmember) {

            if ($addgroupmember->name->__toString() == $searchstring) {
                $member=$addgroupmember->{'addr-group-member'}->{'member'};

                switch ($member->{'type'}->__toString()) {
                    case 1:
                        $retval = $member->{'host-ip-addr'}->__toString();
                        break;
                    case 2:
                        $retval = $member->{'ip-network-addr'}->__toString() . "/" . $member->{'ip-mask'}->__toString();
                        break;
                    case 3:
                        $retval = $member->{'start-ip-addr'}->__toString() . "-" . $member->{'end-ip-addr'}->__toString();
                        break;
                        // TODO: other alias types like alias, groups, etc.
                    case 8:
                        $retval = $member->{'domain'}->__toString();
                        break;
                    default:
                        $retval = "unknown type: " . $member->{'type'}->__toString();
                        print_r($member);
                }
            }
        }
        return $retval;
    }

    /**
     * finds alias references and stores the reference at the object.
     *
     * or at least tries to. could be more sophisticated, but this is
     * a quick start with hitting feels like about 98%
     *
     */
    public function findAliasReferences() {

        foreach ($this->allAliases as $aliasName => $alias) {

            $type = "alias";

            // special case: policy reference: .1.(from|to)
            // naming: ALIAS_NAME.1.from / ALIAS_NAME.1.to
            if (preg_match('/(.+)\.1\.(from|to)$/', $aliasName,$matches)) {
                $type = "policy:$matches[2]";
                $aliasName = $matches[1];
                $policyName = $aliasName . "-00";
                // get all referenced Aliases
                $referencedAliases = $alias->getReferencedAliases();
                switch ($matches[2]) {
                    case "from":
                        if (isset($this->allPolicies[$policyName])) {
                            $this->allPolicies[$policyName]->storeAliasesFrom($referencedAliases);
                        } else {
                            // TODO: print "??? Policy $policyName?\n";
                        }
                        break;
                    case "to":
                        if (isset($this->allPolicies[$policyName])) {
                            $this->allPolicies[$policyName]->storeAliasesTo($referencedAliases);
                        } else {
                            // TODO: print "??? Policy $policyName?\n";
                        }
                        break;
                }


            } else {
                // get all referenced Aliases
                $referencedAliases = $alias->getReferencedAliases();

            }

            // now store this information at the correct alias
            foreach ($referencedAliases as $referencedAlias) {
                $this->allAliases[$referencedAlias]->storeReference($aliasName,$type);
            }

        }

    }

    /**
     * @return array
     */
    public function getTypePortFilter()
    {
        return $this->typePortFilter;
    }

    /**
     * @param array $typePortFilter
     */
    public function setTypePortFilter($typePortFilter)
    {
        $this->typePortFilter = $typePortFilter;
    }

    /**
     * @param string $policyActionFilter
     */
    public function setPolicyActionFilter($policyActionFilter)
    {
        $this->policyActionFilter = $policyActionFilter;
    }

    /**
     * @return array
     */
    public function getPolicyExcludeTypeFilter()
    {
        return $this->policyExcludeTypeFilter;
    }

    /**
     * @param array $policyExcludeTypeFilter
     */
    public function setPolicyExcludeTypeFilter($policyExcludeTypeFilter)
    {
        $this->policyExcludeTypeFilter = $policyExcludeTypeFilter;
    }

    /**
     * @return array
     */
    public function getPolicyTypeFilter()
    {
        return $this->policyTypeFilter;
    }

    /**
     * @param array $policyTypeFilter
     */
    public function setPolicyTypeFilter($policyTypeFilter)
    {
        $this->policyTypeFilter = $policyTypeFilter;
    }

    /**
     * @return array
     */
    public function getPolicyFromFilter()
    {
        return $this->policyFromFilter;
    }

    /**
     * @param array $policyFromFilter
     */
    public function setPolicyFromFilter($policyFromFilter)
    {
        $this->policyFromFilter = $policyFromFilter;
    }

    /**
     * @return array
     */
    public function getPolicyToFilter()
    {
        return $this->policyToFilter;
    }

    /**
     * @param array $policyToFilter
     */
    public function setPolicyToFilter($policyToFilter)
    {
        $this->policyToFilter = $policyToFilter;
    }

    /**
     * @return array
     */
    public function getPolicyTagFilter() {
        return $this->policyTagFilter;
    }

    /**
     * @param array $policyTagFilter
     */
    public function setPolicyTagFilter($policyTagFilter) {
        $this->policyTagFilter = $policyTagFilter;
    }

    /**
     * stores policy references to alias objects
     */
    public function findAliasRefByPolicy() {

        foreach ($this->allPolicies as $policyName => $policy) {

            // get all referenced Aliases
            $referencedAliases = $policy->getReferencedAliases();

            // now store this information at the correct alias
            foreach ($referencedAliases as $referencedAlias) {
                $this->allAliases[$referencedAlias]->storeReference($policyName,"policy");
            }

        }

    }

    /**
     * stores policy references to tags
     *
     * tags are not stored in <policy-list> but in <abs-policy-list>
     * for whatever reason... so loop over abs-policy-list also for tags.
     *
     */
    public function findTagRefByPolicy() {

        foreach ($this->xmlfile->{'abs-policy-list'}->{'abs-policy'} as $policy) {

            $policyName = $policy->name->__toString();

            // <tag-list> is not existend => thus count() is 0. if there are no <tag>s...
            if ($policy->{'tag-list'}->count()) {
                // iterate over all single tags ising xpath
                foreach ($policy->{'tag-list'}->xpath('tag') as $tag) {
                    $tagName = $tag->__toString();
                    $this->allTags[$tagName]->storeReference($policyName,"policy");
                    if (isset($this->allPolicies[$policyName."-00"])) {
                        $this->allPolicies[$policyName."-00"]->storeTag($tagName);
                    } else {
                        if (preg_match("/MUVPN/",$policyName)) {
                            // retry MUVPN-Any.In + MUVPN-Any.Out
                            if (isset($this->allPolicies[$policyName.".In-00"])) {
                                $this->allPolicies[ $policyName . ".In-00" ]->storeTag($tagName);
                            }
                            if (isset($this->allPolicies[$policyName.".Out-00"])) {
                                $this->allPolicies[$policyName.".Out-00"]->storeTag($tagName);
                            }
                        }
                    }
                }

            }

        }

    }

    /**
     * stores policy references to services
     */
    public function findServiceRefByPolicy() {

        foreach ($this->allPolicies as $policyName => $policy) {

            // get PolicyService
            $referencedService = $policy->getService();

            // now store this information at the correct Service
            if (isset($this->allServices[$referencedService])) {
                $this->allServices[$referencedService]->storeReference($policyName, "policy");
            } else {
                // TODO: print "not defined: this->allServices[$referencedService]";
            }

        }

    }

    /**
     * Actions
     **/

    /**
     * lists (all) aliases in this xmlfile
     */
    public function listAllAliases() {
        foreach ($this->allAliases as $aliasName => $alias) {
            // ignore referenced aliases ending .1.from or .1.to or .from.[1234]
            // as these are refs to policies...
            if (preg_match("/(\.1\.(from|to)|\.from\.\d+)$/", $aliasName)) {
                continue;
            }
            $alias->textout($this);
        }
    }

    /**
     * lists (all) tunnels in this xmlfile
     */
    public function listAllTunnels() {
        foreach ($this->allTunnels as $tunnelName => $tunnel) {
            $tunnel->textout($this);
        }
    }

    /**
     * lists (all) policies in this xmlfile
     */
    public function listAllPolicies() {
        global $options;

        foreach ($this->allPolicies as $policyName => $policy) {
            /* @var WatchGuardPolicy $policy */
            $display=true;
            if (count($this->policyTypeFilter)>0) {
                // suppress output if type not in typefilter
                if (!in_array($policy->getService(), $this->policyTypeFilter)) {
                    $display=false;
                }
            }

            if (isset($this->policyActionFilter)) {
                // suppress output if type not in typefilter
                if ($policy->getAction() != $this->policyActionFilter) {
                    $display=false;
                }
            }

            $foundto = false;
            if (count($this->policyToFilter)>0) {
                // suppress output if none of all To aliases match filter-to
                foreach ($policy->getAliasesTo() as $alias) {
                    if (in_array($alias, $this->policyToFilter)) {
                        $foundto = true;
                    };
                }
            }
            $foundfrom = false;
            if (count($this->policyFromFilter)>0) {
                // suppress output if none of all From aliases match filter-from
                foreach ($policy->getAliasesFrom() as $alias) {
                    if (in_array($alias, $this->policyFromFilter)) {
                        $foundfrom = true;
                    };
                }
            }
            if (count($this->policyFromFilter)>0 && count($this->policyToFilter)>0) {
                if (!($foundfrom && $foundto)) {
                    $display=false;
                }
            } elseif (count($this->policyFromFilter)>0 || count($this->policyToFilter)>0) {
                if (!($foundfrom || $foundto)) {
                    $display = false;
                }
            }

            if (
                // if filter is set to enabled: supress disabled
                (isset($options['enabled']) && $policy->isEnabled() === false)
                ||
                // if filter is set to disabled: supress enabled
                (isset($options['disabled']) && $policy->isEnabled() === true)) {

                $display = false;
            }

            if (count($this->getPolicyExcludeTypeFilter())>0) {
                if (in_array($policy->getService(), $this->getPolicyExcludeTypeFilter())) {
                    $display = false;
                }
            }

            if (count($this->getPolicyTagFilter())>0) {
                $found=false;
                foreach($policy->getTags() as $tagname) {
                    if (in_array($tagname, $this->getPolicyTagFilter())) {
                        $found=true;
                    }
                }
                if ($found==false) {
                    $display=false;
                }
            }

            if ($display==true) {
                $policy->textout($this);
            }
        }
    }

    /**
     * lists (all) tags in this xmlfile
     */
    public function listAllTags() {
        foreach ($this->allTags as $tagName => $tag) {
            $tag->textout($this);
        }
    }

    /**
     * lists (all) services in this xmlfile
     */
    public function listAllServices() {
        foreach ($this->allServices as $serviceName => $service) {
            /** @var WatchGuardService $service */
            $display=true;
            if (count($this->policyTypeFilter)>0) {
                // suppress output if type not in typefilter
                if (!in_array($serviceName, $this->policyTypeFilter)) {
                    $display=false;
                }
            }
            if (count($this->policyExcludeTypeFilter)>0) {
                // suppress output if type in typeExcludeFilter
                if (in_array($serviceName, $this->policyExcludeTypeFilter)) {
                    $display=false;
                }
            }
            if (count($this->typePortFilter)>0) {
                // suppress output if type not in typefilter
                $found=false;
                foreach($service->getServicePorts() as $port) {
                   if (in_array($port, $this->typePortFilter)) {
                       $found=true;
                   }
                }
                if ($found==false) {
                    $display=false;
                }
            }
            if ($display==true) {
                $service->textout($this);
            }
        }
    }

    /**
     * prints one single alias
     * @param $aliasname
     */
    public function printAlias($aliasname) {
        if (isset($this->allAliases[$aliasname])) {
            $this->allAliases[$aliasname]->textout($this);
        } else {
            displayHelpAndError("alias '$aliasname' not found.");
        }
    }

    public function printInfo() {

        $multiwan = new WatchGuardMultiWan($this->xmlfile->{'system-parameters'}->{'multi-wan'});
        $sso = new WatchGuardSSO($this->xmlfile->{'system-parameters'}->{'single-sign-on'});
        $misc = new WatchGuardMiscSettings($this->xmlfile->{'system-parameters'}->{'misc-global-setting'});
        // $sso->debug();

        printf("\nXML-file Info\n\n");
        printf("%-30s%-49s\n", "Auto-Order:", $misc->getAutoOrder());

        printf("\nNetworking:\n");
        printf("%-30s%-49s\n", "Multi-WAN:", $multiwan->getAlgorithm(). ' (' . $multiwan->getAlgorithmText() . ')');
        printf("%-30s%-49s\n", "MTU-Probing:", $misc->getMTUProbing());
        printf("%-30s%-49s\n", "Auto-Reboot:", $misc->getAutoReboot());
        printf("%-30s%-49s\n", "QoS:", $misc->getQoS());
        printf("%-30s%-49s\n", "BlockSpoofedPackets:", $misc->getBlockSpoofEnabled());
        printf("%-30s%-49s\n", "SynCheckingEnabled:", $misc->getSynChecking());
        printf("%-30s%-49s\n", "VLAN-Forwarding:", $misc->getVlanForward());

        printf("\nOther:\n");
        printf("%-30s%-49s\n", "SSO-Settings:", $sso->isEnabled() . ' ' .  $sso->getSSOAgents());

        printf("\n\n");
    }

    public function printWarnings() {

        $warnings = 0;
        $multiwan = new WatchGuardMultiWan($this->xmlfile->{'system-parameters'}->{'multi-wan'});
        $sso = new WatchGuardSSO($this->xmlfile->{'system-parameters'}->{'single-sign-on'});
        $misc = new WatchGuardMiscSettings($this->xmlfile->{'system-parameters'}->{'misc-global-setting'});

        printf("\nXML-file Warnings\n\n");
        if ($misc->getAutoOrder()==0) {
            printf("%-30s%-49s\n", "Auto-Order:", $misc->getAutoOrder());
            $warnings++;
        }

        if (!in_array($multiwan->getAlgorithm(), array("0","2"))) {
            printf("%-30s%-49s\n", "Multi-WAN:", $multiwan->getAlgorithm(). ' (' . $multiwan->getAlgorithmText() . ')');
            $warnings++;
        }

        if ($misc->getMTUProbing()!=2) {
            printf("%-30s%-49s\n", "Multi-WAN:", $multiwan->MTUProbing());
            $warnings++;
        }

        if ($misc->getAutoReboot()==1) {
            printf("%-30s%-49s\n", "Auto-Reboot:", $misc->getAutoReboot());
            $warnings++;
        }

        printf("\nSumnary:\n");
        printf("%-30s%-49s\n", "Total Warnings:", $warnings);
        printf("\n\n");
    }
}