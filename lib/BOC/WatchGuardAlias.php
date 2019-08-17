<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardAlias
{
    private $alias;

    public function __construct(SimpleXMLElement $element) {
        $this->alias = $element;
    }

    public function textout($xmlfile) {

        $retval = null;

        print $this->alias->name . "\n";
        $memberlist = $this->alias->{'alias-member-list'};

        for ($nr=0; $nr < count($memberlist->{'alias-member'}); $nr++) {

            $content = "";
            $member = $memberlist->{'alias-member'}[$nr];
            $type = $member->type;

            switch ($type) {
                case 1:
                    $value = $memberlist->{'alias-member'}[$nr]->address->__toString();
                    $content = $xmlfile->resolveAliasAddress($value);
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
        return $retval;
    }

}

