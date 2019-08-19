<?php

namespace BOC;

// use BOC\WatchGuardAlias;
use SimpleXMLElement;

class WatchGuardXMLFile
{
    private $xmlfile;       // complete xml structure as SimpleXML object

    // arrays for all aliases, policies and services:
    private $allAliases;
    private $allPolicies;
    private $allServices;

    public function __construct($xmlfilename) {
        $this->xmlfile = simplexml_load_file($xmlfilename);
        $this->allAliases  = [];
        $this->allPolicies = [];
        $this->allServices = [];

        $this->getAllAliases();
        $this->getAllPolicies();
        $this->getAllServices();
        $this->findAliasReferences();
        $this->findServiceRefByPolicy();
    }

    /**
     * Helpers
     **/
    private function getAllAliases() {

        foreach ($this->xmlfile->{'alias-list'}->children() as $alias) {
            $this->allAliases[$alias->name->__toString()] = new WatchGuardAlias($alias);
        }

    }

    private function getAllPolicies() {

        foreach ($this->xmlfile->{'policy-list'}->{'policy'} as $policy) {
            $policyName = $policy->name->__toString();
            $this->allPolicies[$policyName] = new WatchGuardPolicy($policy);
            $this->allPolicies[$policyName]->getReferencedAliases();
        }

    }

    private function getAllServices() {

        foreach ($this->xmlfile->{'service-list'}->children() as $service) {
            $this->allServices[$service->name->__toString()] = new WatchGuardService($service);
        }

    }

    private function getXMLObject(SimpleXMLElement $obj,$searchname) {
        $retval = null;

        foreach ($obj->children() as $child) {

            $name = $child->getName();
            if ($name != $searchname) continue;
            $retval = $child;
        }
        return $retval;
    }

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
                            print "??? Policy $policyName?\n";
                        }
                        break;
                    case "to":
                        if (isset($this->allPolicies[$policyName])) {
                            $this->allPolicies[$policyName]->storeAliasesTo($referencedAliases);
                        } else {
                            print "??? Policy $policyName?\n";
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

    public function findAliasRefByPolicy() {

        foreach ($this->allPolicies as $policyName => $policy) {

            // get all referenced Aliases
            $referencedAliases = $policy->getReferencedAliases();

            // now store this information at the correct alias
            foreach ($referencedAliases as $referencedAlias) {
                $this->allAliases[$referencedAlias]->storeReference($aliasName,"policy");
            }

        }

    }

    public function findServiceRefByPolicy() {

        foreach ($this->allPolicies as $policyName => $policy) {

            // get PolicyService
            $referencedService = $policy->getService();

            // now store this information at the correct Service
            $this->allServices[$referencedService]->storeReference($policyName,"policy");

        }

    }

    /**
     * Actions
     **/
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

    public function listAllPolicies() {
        foreach ($this->allPolicies as $policyName => $policy) {
            $policy->textout($this);
        }
    }

    public function listAllServices() {
        foreach ($this->allServices as $serviceName => $service) {
            $service->textout($this);
        }
    }

    public function printAlias($aliasname) {
        if (isset($this->allAliases[$aliasname])) {
            $this->allAliases[$aliasname]->textout($this);
        } else {
            displayHelpAndError("alias '$aliasname' not found.");
        }
    }
}