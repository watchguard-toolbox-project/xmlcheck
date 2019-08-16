<?php

namespace BOC;

class WatchGuardXMLFile
{
    private $xmlfile;
    private $xml_alias_list;
    private $xml_policy_list;

    public function __construct($xmlfilename) {
        $this->xmlfile = simplexml_load_file($xmlfilename);
        $this->xml_alias_list = $this::getAliasList($this->xmlfile);
        $this->xml_policy_list = $this::getPolicyList($this->xmlfile);
    }

    private function getAliasList($xml) {
        foreach ($xml->children() as $child) {

            $name = $child->getName();
            if ($name != "alias-list") continue;
            return $child;
        }
    }

    private function getPolicyList($xml) {
        foreach ($xml->children() as $child) {

            $name = $child->getName();
            if ($name != "policy-list") continue;
            return $child;
        }
    }

    public function listAllAliases() {
        foreach ($this->xml_alias_list->children() as $alias) {
            // ignore referenced aliases ending .1.from or .1.to or .from.[1234]
            if (preg_match("/(\.1\.(from|to)|\.from\.\d+)$/", $alias->name)) {
                continue;
            }
            print $alias->name . "\n";
        }
    }

    public function listAllPolicies() {
        foreach ($this->xml_policy_list->children() as $policy) {
            // ignore policies aliases ending .1.from or .1.to or .from.[1234]
            /*
            if (preg_match("/(\.1\.(from|to)|\.from\.\d+)$/", $policy->name)) {
                continue;
            }
            */
            print $policy->name . "\n";
        }
    }

}