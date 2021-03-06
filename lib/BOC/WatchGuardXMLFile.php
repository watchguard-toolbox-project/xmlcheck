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
        $this->allTags = [];

        // initialize aliases, services and tags
        $this->getAllAliases();
        $this->getAllServices();
        $this->getAllTags();

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
     * lists (all) policies in this xmlfile
     */
    public function listAllPolicies() {
        foreach ($this->allPolicies as $policyName => $policy) {
            $policy->textout($this);
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
            $service->textout($this);
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
}