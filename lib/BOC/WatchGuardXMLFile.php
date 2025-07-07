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
use BOC\WatchGuardDeviceConf;
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
     * array for filter-exclude-name
     * @var array
     */
    private $policyExcludeNameFilter;
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
     * array for filter-name
     * @var array
     */
    private $policyNameFilter;
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
     * array for all nats from this xmlfile
     * @var array
     */
    private $allNats;

    /**
     * array for outputbuffering
     * @var array
     */
    private $output = [];

    /**
     * array for outputbuffering, used to create json object
     * @var array
     */
    private $jsonoutput = [];

    /**
     * WatchGuardXMLFile constructor.
     *
     * loads the xmlfile, initializes all aliases, policies and services.
     *
     * @param $xmlfilename
     */
    public function __construct($xmlfilename) {
        global $options;
        libxml_use_internal_errors(true);
        $this->xmlfile = simplexml_load_file($xmlfilename);
        if ($this->xmlfile === false) {
            // don't use die, for possibility to check error-level (failure)
            //fwrite (STDERR, "errmsg");
            //fwrite (STDOUT, "errmsg");
            print "Error: $xmlfilename is not a valid xml file.\n";
            if (isset($options['verbose']) && $options['verbose']==true) {
                foreach (libxml_get_errors() as $error) {
                    print($error->message);
                }
            }
            exit(1);
        }
        $this->allAliases  = [];
        $this->allPolicies = [];
        $this->allServices = [];
        $this->allTunnels = [];
        $this->allTags = [];

        // initialize filters as arrays
        // don't initialize policyActionFilter as it is no array.
        $this->policyNameFilter = [];
        $this->policyFromFilter = [];
        $this->policyToFilter = [];
        $this->policyTypeFilter = [];
        $this->policyTagFilter = [];

        $this->policyExcludeTypeFilter = [];
        $this->policyExcludeNameFilter = [];

        // initialize aliases, services and tags
        $this->getAllAliases();
        $this->getAllServices();
        $this->getAllTags();
        $this->getAllTunnels();
        $this->getAllNats();

        // initialize policies (gets also references to tags and aliases)
        $this->getAllPolicies();

        // now find aliases in aliases
        $this->findAliasReferences();
        $this->findServiceRefByPolicy();
        $this->findTagRefByPolicy();
    }

    /**
     * reads all nats from xml and sets the pointer into nats array
     **/
    private function getAllNats() {

        foreach ($this->xmlfile->{'nat-list'}->children() as $nat) {
            $this->allNats[$nat->name->__toString()] = new WatchGuardNat($nat);
        }
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
     * returns ONE alias
     **/
    private function getAliasByName($name) {
        return $this->allAliases[$name];
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

        if ($this->xmlfile->{'policy-tag-list'}->children() != null) {
            foreach ($this->xmlfile->{'policy-tag-list'}->children() as $tag) {
                $this->allTags[$tag->name->__toString()] = new WatchGuardTag($tag, 'tags');
            }
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
            $prettyName = $this->allPolicies[$policyName]->getNamePretty();
            $this->allPolicies[$policyName]->setFirewallAction($this->findPolicyAction($prettyName));
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
     * @return array
     */
    public function getOutput()
    {
        return $this->output;
    }

    /**
     * @return array
     */
    public function getJsonOutput()
    {
        return $this->jsonoutput;
    }

    /**
     * @return array
     */
    public function getPolicyNameFilter()
    {
        return $this->policyNameFilter;
    }

    /**
     * @param array $policyNameFilter
     */
    public function setPolicyNameFilter($policyNameFilter)
    {
        $this->policyNameFilter = $policyNameFilter;
    }

    /**
     * @return array
     */
    public function getPolicyExcludeNameFilter()
    {
        return $this->policyExcludeNameFilter;
    }

    /**
     * @param array $policyExcludeNameFilter
     */
    public function setPolicyExcludeNameFilter($policyExcludeNameFilter)
    {
        $this->policyExcludeNameFilter = $policyExcludeNameFilter;
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
                $policyName = $aliasName;
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
     * finds policy action
     *
     * actions are stored in <policy-list> AND in <abs-policy-list>
     * for whatever reason... so loop over abs-policy-list also for tags.
     *
     */
    public function findPolicyAction ($policyName) {
        foreach ($this->xmlfile->{'abs-policy-list'}->{'abs-policy'} as $policy) {
            if ($policy->name->__toString() == $policyName) {
                // print_r($policyName);
               return $policy->firewall->__toString();
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
     * prepare (all) aliases in this xmlfile
     */
    public function prepareAllAliases($index,$name="") {
        global $options;

        if ($name=="") $name=$index;
        $this->output = [];

        foreach ($this->allAliases as $aliasName => $alias) {
            // ignore referenced aliases ending .1.from or .1.to or .from.[1234]
            // as these are refs to policies...
            if (preg_match("/(\.1\.(from|to)|\.from\.\d+)$/", $aliasName)) {
                continue;
            }
            $this->output[] = $alias;
        }

        if ((isset($options['json']) && $options['json']==true) ||
            (isset($options['fwcheck']) && $options['fwcheck']==true)) {

            $this->jsonoutput[$index]= [];
            $this->jsonoutput[$index.'_unused']= [];
            foreach ($this->output as $alias) {
                if (preg_match('/(Built-in alias)/',$alias->getDescriptionPretty())) {
                    continue;
                }
                if (preg_match('/\.(from|to|snat)$/',$alias->getNamePretty())) {
                    continue;
                }
                if (preg_match('/^(Any|Any-(BOVPN|MUVPN|Trusted|Optional|External|Multicast)|Firebox)$/',$alias->getNamePretty())) {
                    continue;
                }
                $unused="";
                if ($alias->isUnused()) {
                    $unused=" (unused)";
                    $this->jsonoutput[$index.'_unused'][]= [
                        "name" => $alias->getNamePretty().$unused,
                        "comment" => $alias->getDescriptionPretty() ];
                }
                $this->jsonoutput[$index][]= [
                    "name" => $alias->getNamePretty().$unused,
                    "comment" => $alias->getDescriptionPretty() ];

            }
            $this->jsonoutput[$index."_count"]['name']='Aliases';
            $this->jsonoutput[$index."_count"]['value']= count($this->jsonoutput[$index]);
            $this->jsonoutput[$index."_count"]['info']='';
            $this->jsonoutput[$index."_unused_count"]['name']='Unused Aliases';
            $this->jsonoutput[$index."_unused_count"]['value']= count($this->jsonoutput[$index.'_unused']);
            $this->jsonoutput[$index."_unused_count"]['info']='';
        }
    }

    /**
     * lists (all) aliases in this xmlfile
     */
    public function listAllAliases() {

        global $options;

        $this->prepareAllAliases('aliases');

        if ((isset($options['json']) && $options['json']==true) ||
            (isset($options['fwcheck']) && $options['fwcheck']==true)) {
            // do nothing;
        } else {
            foreach ($this->output as $alias) {
                $alias->textout($this);
            }
        }
    }

    public function getAliasCount() {
        $count=0;
        foreach ($this->allAliases as $aliasName => $alias) {
            // ignore referenced aliases ending .1.from or .1.to or .from.[1234]
            // as these are refs to policies...
            if (preg_match("/((\.1\.(from|to)|\.(from|to)(\.\d+)?)$|".
                    "^".
                    "(Any|Firebox|PPTP|SSL-VPN|External|Trusted|Optional|".
                    ".*\.snat|".
                    "Any-(Trusted|Optional|External|MUVPN)|Any-BOVPN)".
                    "$)/", $aliasName)
                ) {
                continue;
            } else {
                $count++;
            }
        }
        return $count;
    }

    /**
     * lists (all) nats in this xmlfile
     */
    public function listAllNats() {
        foreach ($this->allNats as $natName => $nat) {
            $nat->textout($this);
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
    public function prepareAllPolicies($index, $name='') {
        global $options;

        $this->prepareAllAliases('aliases');

        if ($name=='') $name=$index;
        $this->output = [];

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
                // search for From and To
                if (!($foundfrom && $foundto)) {
                    $display=false;
                }
            } elseif (count($this->policyFromFilter)>0 || count($this->policyToFilter)>0) {
                // search for to OR from
                if (!($foundfrom || $foundto)) {
                    $display = false;
                }
            }

            if (count($this->policyNameFilter)>0) {
                // suppress output no name matches
                $found = false;
                foreach ($this->policyNameFilter as $namefilter) {
                    // $namefilter array elements must be valid regexp,
                    // this is checked before values are pushed to $namefilter
                    if (preg_match($namefilter, $policyName)) {
                        $found = true;
                    }
                }
                if (!$found) {
                    $display = false;
                }
            }

            if (count($this->policyExcludeNameFilter)>0) {
                // suppress output where name matches
                foreach ($this->policyExcludeNameFilter as $namefilter) {
                    // $namefilter array elements must be valid regexp,
                    // this is checked before values are pushed to $namefilter
                    if (preg_match($namefilter, $policyName)) {
                        $display = false;
                    }
                }
            }

            if (count($this->policyFromFilter)>0) {
                // suppress output if none of all From aliases match filter-from
                foreach ($policy->getAliasesFrom() as $alias) {
                    if (in_array($alias, $this->policyFromFilter)) {
                        $foundfrom = true;
                    };
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
                $this->output[] = $policy;
            }
        }

        if ( !((isset($options['json']) && $options['json']==false) ||
               (isset($options['fwcheck']) && $options['fwcheck']==false)) ) {

            $this->jsonoutput[$index]= [];
            $order=1;
            foreach ($this->output as $policy) {
                # print_r($policy);

                $aliasesTo=[];
                foreach ( $policy->getReferencedAliasesTo() as $alias) {
                    $aliasesTo[] = $this->getAliasByName($alias);
                };

                $aliasesToNames=[];
                foreach ($aliasesTo as $alias) {
                    if (preg_match("/(Any|Firebox)/", $alias->getName())) {
                        $aliasesToNames[] = $alias->getName();
                    }
                    else $aliasesToNames = $alias->getReferencedAliases();
                }

                $aliasesFrom=[];
                foreach ( $policy->getReferencedAliasesFrom() as $alias) {
                    $aliasesFrom[] = $this->getAliasByName($alias);
                }

                $aliasesFromNames=[];
                foreach ($aliasesFrom as $alias) {
                    if (preg_match("/(Any|Firebox)/", $alias->getName())) {
                        $aliasesFromNames[] = $alias->getName();
                    }
                    else $aliasesFromNames = $alias->getReferencedAliases();
                }

                $this->jsonoutput[$index][]= [
                    "order" => $order++,
                    "name" => $policy->getNamePretty(),
                    "action" => $policy->getAction(),
                    "type" => $policy->getType(),
                    "from" => $aliasesFromNames,
                    "to" => $aliasesToNames,
                    "comment" => $policy->getDescriptionPretty(),
                    "tags" => $policy->getTags(),
                    "enabled" => $policy->isEnabled(),
                    "firewall" => $policy->getFirewallAction() ];
            }
            $this->jsonoutput[$index."_count"]['name']=$name;
            $this->jsonoutput[$index."_count"]['value']= count($this->jsonoutput[$index]);
            $this->jsonoutput[$index."_count"]['info']='';
        }
    }
    /**
     * lists (all) policies in this xmlfile
     */
    public function listAllPolicies($index='policies') {


        global $options;

        $this->prepareAllPolicies($index);

        foreach ($this->output as $policy) {
            if ((!isset($options['json']) || $options['json']==false) &&
                (!isset($options['fwcheck']) || $options['fwcheck']==false)) {
                $policy->textout($this);
            }
        }
        if ((isset($options['json']) && $options['json']==true) ||
            (isset($options['fwcheck']) && $options['fwcheck']==true)) {
            $this->printJsonOutput($options);
        }
    }

    /**
     * lists (all) tags in this xmlfile
     */
    public function listAllTags() {
        global $options;

        $type='tags';
        $this->jsonoutput[$type]=[];
        $this->jsonoutput[$type.'_unused']=[];

        foreach ($this->allTags as $tagName => $tag) {
            if ((isset($options['json']) && $options['json']==true) ||
            (isset($options['fwcheck']) && $options['fwcheck']==true)) {
                $tag->prepareJson($tag, $type);
                $arr = $tag->getJsonObject();
                if (isset($arr[$type])) {
                    $this->jsonoutput[$type]=array_merge($this->jsonoutput[$type],$arr[$type]);
                }
                if (isset($arr[$type.'_unused'])) {
                    // unused show up on all aliases as well
                    $this->jsonoutput[$type]=array_merge($this->jsonoutput[$type],$arr[$type.'_unused']);
                    $this->jsonoutput[$type.'_unused']=array_merge($this->jsonoutput[$type.'_unused'],$arr[$type.'_unused']);
                }
            } else {
                $tag->textout($this);
            }
        }
        if ((isset($options['json']) && $options['json']==true) ||
            (isset($options['fwcheck']) && $options['fwcheck']==true)) {
            $this->jsonoutput[$type.'_count']['name'] = 'Tags';
            $this->jsonoutput[$type.'_count']['value'] = count($this->jsonoutput[$type]);
            $this->jsonoutput[$type.'_count']['info'] = '';
            $this->jsonoutput[$type.'_unused_count']['name'] = 'Unused Tags';
            $this->jsonoutput[$type.'_unused_count']['value'] = count($this->jsonoutput[$type.'_unused']);
            $this->jsonoutput[$type.'_unused_count']['info'] = '';
        }

        if (!isset($options['fwcheck']) || $options['fwcheck']==false) {
            $this->printJsonOutput($options);
        }
    }

    /**
     * lists (all) services in this xmlfile
     */
    public function listAllServices() {
        global $options;
        $type='types';
        $this->jsonoutput[$type]=[];
        $this->jsonoutput[$type.'_unused']=[];

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
            if (isset($this->typePortFilter) && count($this->typePortFilter)>0) {
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

            if ($service->isDefault()) {
                $display=false;
            }

            // valid type?
            if ($display==true) {
                if ((isset($options['json']) && $options['json']==true) ||
                    (isset($options['fwcheck']) && $options['fwcheck']==true)) {
                    $service->prepareJson($service);
                    $arr = $service->getJsonObject();
                    if (isset($arr[$type])) {
                        $this->jsonoutput[$type]=array_merge($this->jsonoutput[$type],$arr[$type]);
                    }
                    if (isset($arr[$type.'_unused'])) {
                        // unused show up on all aliases as well
                        $this->jsonoutput[$type]=array_merge($this->jsonoutput[$type],$arr[$type.'_unused']);
                        $this->jsonoutput[$type.'_unused']=array_merge($this->jsonoutput[$type.'_unused'],$arr[$type.'_unused']);
                    }
                } else {
                    $service->textout($this);
                }
            }
        }
        if ((isset($options['json']) && $options['json']==true) ||
            (isset($options['fwcheck']) && $options['fwcheck']==true)) {
            $this->jsonoutput[$type.'_count']['name'] = 'Types';
            $this->jsonoutput[$type.'_count']['value'] = count($this->jsonoutput[$type]);
            $this->jsonoutput[$type.'_count']['info'] = '';
            $this->jsonoutput[$type.'_unused_count']['name'] = 'Unused Types';
            $this->jsonoutput[$type.'_unused_count']['value'] = count($this->jsonoutput[$type.'_unused']);
            $this->jsonoutput[$type.'_unused_count']['info'] = '';
        }

        // if --list-tpyes is called w/ --json
        if (!isset($options['fwcheck']) || $options['fwcheck']==false) {
            $this->printJsonOutput($options);
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

    public function printInfo($format="text") {

        $multiwan = new WatchGuardMultiWan($this->xmlfile);
        $sso = new WatchGuardSSO($this->xmlfile);
        $sysparm = new WatchGuardSystemParameters($this->xmlfile);
        $misc = new WatchGuardMiscSettings($this->xmlfile);
        $device = new WatchGuardDeviceConf($this->xmlfile);
        $cluster = new WatchGuardCluster($this->xmlfile);
        $version = new WatchGuardXMLVersion($this->xmlfile);
        $sslvpn = new WatchGuardSSLVPN($this->xmlfile);

        // $sso->debug();

        $v = [];

        $v[] = ['setting' => 'System-Name',
            'value'   => $device->getSystemName(),
            'info'    => '' ];
        $v[] = ['setting' => 'Model',
            'value'   => $device->getModel(),
            'info'    => '' ];
        $v[] = ['setting' => 'Firmware-Version',
            'value'   => $version->getVersion(),
            'info'    => '' ];

        $v[] = ['setting' => 'ClusterEnabled',
            'value'   => $cluster->isEnabled(),
            'info'    => '' ];

        $v[] = ['setting' => 'Policies',
            'value'   => count($this->allPolicies),
            'info'    => '' ];
        $v[] = ['setting' => 'Aliases',
            'value'   => $this->getAliasCount(),
            'info'    => '' ];
        $v[] = ['setting' => 'Tags',
            'value'   => count($this->allTags),
            'info'    => '' ];
        $v[] = ['setting' => 'Auto-Order',
                'value'   => $misc->getAutoOrder(),
                'info'    => '' ];

        $v[] = ['setting'  => 'Multi-WAN',
                'value'   => $multiwan->getAlgorithm(),
                'info'    => '(' . $multiwan->getAlgorithmText() . ')' ];
        $v[] = ['setting' => 'MTU-Probing',
                'value'   => $misc->getMTUProbing(),
                'info'    => '' ];
        $v[] = ['setting' => 'QoS',
                'value'   => $misc->getQoS(),
                'info'    => '' ];
        $v[] = ['setting' => 'BlockSpoofedPackets',
                'value'   => $misc->getBlockSpoofEnabled(),
                'info'    => '' ];
        $v[] = ['setting' => 'SynCheckingEnabled',
                'value'   => $misc->getSynChecking(),
                'info'    => '' ];
        $v[] = ['setting' => 'VLAN-Forwarding',
                'value'   => $misc->getVlanForward(),
                'info'    => '' ];
        $v[] = ['setting' => 'Auto-Reboot',
            'value'   => $misc->getAutoReboot(),
            'info'    => $misc->getAutoRebootTime() ];
        $v[] = ['setting' => 'AutoBlockDuration',
            'value'   => $misc->getAutoBlockedDuration(),
            'info'    => '' ];


        $v[] = ['setting' => 'SSO-Settings',
            'value'   => $sso->isEnabled(),
            'info'    => $sso->getSSOAgents() ];

        $v[] = ['setting' => 'FeatureKeyAutoSync',
            'value'   => $sysparm->featureKeyAutoSyncIsEnabled(),
            'info'    => '' ];

        $v[] = ['setting' => 'WatchGuardCloud',
            'value'   => $sysparm->isWatchGuardCloudEnabled(),
            'info'    => '' ];


        $v[] = ['setting' => 'SSLVPN-enabled',
                'value'   => $sslvpn->isEnabled(),
                'info'    => '' ];

        if ($sslvpn->isEnabled()) {
            $v[] = ['setting' => 'SSLVPN-autoreconnect',
                'value'   => $sslvpn->isAutoRecoonect(),
                'info'    => '' ];
            $v[] = ['setting' => 'SSLVPN-renegDataChannel',
                'value'   => $sslvpn->renegDataChannel(),
                'info'    => '' ];
        }



        /*
        $v[] = ['setting' => 'Foo-Setting',
            'value'   => '1',
            'info'    => 'foo bar test' ];
        */


        if ($format == 'text') {

            printf("\nXML-file Info\n\n");
            printf("\nDevice-Info:\n");
            foreach ($v as $row => $values) {
                printf("%-30s%-49s\n", $values['setting'] . ":", $values['value']);

                if ($values['setting'] == "Firmware-Version") {
                    printf("\nCluster-Info:\n");
                }
                if ($values['setting'] == "ClusterEnabled") {
                    printf("\nPolicy-Info:\n");
                }
                if ($values['setting'] == "Auto-Order") {
                    printf("\nNetworking:\n");
                }
                if ($values['setting'] == "VLAN-Forwarding") {
                    printf("\nOther:\n");
                }
            }

            printf("\n\n");

        }

        foreach ($v as $row => $values) {
            $this->jsonoutput['setting'][$values['setting']] = $values;
        }
    }

    public function printWarnings() {

        $warnings = 0;

        $multiwan = new WatchGuardMultiWan($this->xmlfile);
        $sso = new WatchGuardSSO($this->xmlfile);
        $misc = new WatchGuardMiscSettings($this->xmlfile);


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
            printf("%-30s%-49s\n", "MTU-Probing:", $misc->getMTUProbing());
            $warnings++;
        }

        if ($misc->getAutoReboot()==1) {
            printf("%-30s%-49s\n", "Auto-Reboot:", $misc->getAutoReboot());
            $warnings++;
        }

        if ($misc->getAutoBlockedDuration()==1200) {
            printf("%-30s%-49s\n", "Auto-BlockedDuration:", $misc->getAutoBlockedDuration());
            $warnings++;
        }

        printf("\nSummary:\n");
        printf("%-30s%-49s\n", "Total Warnings:", $warnings);
        printf("\n\n");
    }

    /**
     * @return void
     */
    public function printJsonOutput($options) {
        $flags = null;
        if (isset($options['json-pretty'])) {
            $flags= JSON_PRETTY_PRINT;
        }
        if (isset($options['json'])) {
            print (json_encode($this->getJsonOutput(), $flags));
        }
    }
}