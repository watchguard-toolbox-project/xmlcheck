<?php

namespace BOC;

// use BOC\WatchGuardAlias;
use SimpleXMLElement;

class WatchGuardXMLFile
{
    private $xmlfile;
    private $xml_policy_list;
    private $allAliases;
    private $allPolicies;

    public function __construct($xmlfilename) {
        $this->xmlfile = simplexml_load_file($xmlfilename);
        $this->xml_policy_list = $this::getPolicyList($this->xmlfile);
        $this->getAllAliases();
        $this->getAllPolicies();
    }

    private function getAllAliases() {

        $this->allAliases = Array();
        foreach ($this->xmlfile->{'alias-list'}->children() as $alias) {
            // ignore referenced aliases ending .1.from or .1.to or .from.[1234]
            if (preg_match("/(\.1\.(from|to)|\.from\.\d+)$/", $alias->name)) {
                continue;
            }
            $this->allAliases[$alias->name->__toString()] = new WatchGuardAlias($alias);
        }
    }

    private function getAllPolicies() {

        $this->allPolicies = Array();
        foreach ($this->xmlfile->{'policy-list'}->children() as $policy) {
            $this->allPolicies[$policy->name->__toString()] = new WatchGuardPolicy($policy);
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

    private function getPolicyList($xml) {
        return $xml->{'policy-list'};
    }

    public function listAllAliases() {
        foreach ($this->allAliases as $aliasName => $alias) {
            $alias->textout($this);
        }
    }

    public function listAllPolicies() {
        foreach ($this->allPolicies as $policyName => $policy) {
            $policy->textout($this);
        }
    }

    public function resolveAliasAddress($searchstring)
    {

        $retval="";
        $addressGroup = $this->xmlfile->{'address-group-list'}->{'address-group'};

        for ($nr = 0; $nr < count($addressGroup); $nr++) {

            $addgroupmember = $addressGroup[$nr];
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

    public function printAlias($aliasname) {
        $this->allAliases[$aliasname]->textout($this);
    }
}