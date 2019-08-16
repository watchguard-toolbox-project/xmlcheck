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

    private function getXMLObject($obj,$searchname) {
        foreach ($obj->children() as $child) {

            $name = $child->getName();
            if ($name != $searchname) continue;
            return $child;
        }
    }

    private function getAliasList($xml) {
        return $xml->{'alias-list'};
    }

    private function getPolicyList($xml) {
        return $xml->{'policy-list'};
    }

    private function getAliasMemberList($alias) {
        return $alias->{'alias-member-list'};
    }

    private function getAliasMember($obj) {
        return $obj->{'alias-member'};
    }

    public function listAllAliases() {
        foreach ($this->xml_alias_list->children() as $alias) {
            // ignore referenced aliases ending .1.from or .1.to or .from.[1234]
            if (preg_match("/(\.1\.(from|to)|\.from\.\d+)$/", $alias->name)) {
                continue;
            }
            $this->printAlias($alias->name);
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

        foreach ($this->xml_alias_list->children() as $alias) {
            if ($alias->name != $aliasname) {
                continue;
            }
            print $alias->name . "\n";

            $memberlist = $alias->{'alias-member-list'};
            for ($nr=0; $nr < count($memberlist->{'alias-member'}); $nr++) {
                $member = $memberlist->{'alias-member'}[$nr];
                $type = $member->type;
                $content = "";
                switch ($type) {
                    case 1:
                        $value = $memberlist->{'alias-member'}[$nr]->address->__toString();
                        $content = $this->resolveAliasAddress($value);
                        break;
                    case 2:
                        $value = $memberlist->{'alias-member'}[$nr]->{'alias-name'};
                        break;
                    default:
                        $value = "unknown type";
                }
                printf ("%-02d  type: %d   value: %s => %s\n", $nr, $type, $value, $content);
                if ($value == "unknown type") {
                    print_r($member);
                }
            }
        }
    }
}