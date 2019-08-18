<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardService
{
    private $service;

    public function __construct(SimpleXMLElement $element) {
        $this->service = $element;
    }

    private function getReferencedAliasesFromAliasList($list) {

        $retval = [];

        for ($nr=0; $nr < count($memberlist->{'alias-member'}); $nr++) {

            $member = $memberlist->{'alias-member'}[$nr];

            // see only aliases, type==2
            if ($member->type == 2) {
                $retval[] = $member->{'alias-name'}->__toString();
            }

        }


    }

    public function getReferencedAliases() {

        $retval = [];

        $memberlist = $this->policy->{'from-alias-list'};
        $retval = array_merge($retval, $this->getReferencedAliasesFromAliasList($memberlist));

        $memberlist = $this->policy->{'to-alias-list'};
        $retval = array_merge($retval, $this->getReferencedAliasesFromAliasList($memberlist));

        return $retval;
    }

    public function textout($xmlfile) {
        print $this->policy->name->__toString() . "\n";
    }

}
