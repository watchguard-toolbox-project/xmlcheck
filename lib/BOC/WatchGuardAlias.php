<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardAlias
{
    private $alias;
    private $referencedBy;
    private $refcount;
    private $aliastype;

    public function __construct(SimpleXMLElement $element)
    {
        $this->alias = $element;
        $this->referencedBy = [];
        $this->refcount = 0;

        $members = $this->alias->{'alias-member-list'}->{'alias-member'};
        if (count($members) == 1) {
            // only one member, check for interface...
            $member = $members[0];
            $type = $member->type;

            if ($type == 1 && $member->interface->__toString() != "Any") {
                $this->aliastype = "interface";
            } else {
                $this->aliastype = "other";
            }
        }
    }

        public function getReferencedAliases() {

        $retval = [];

        $memberlist = $this->alias->{'alias-member-list'};

        for ($nr=0; $nr < count($memberlist->{'alias-member'}); $nr++) {

            $member = $memberlist->{'alias-member'}[$nr];

            // see only aliases, type==2
            if ($member->type == 2) {
                $retval[] = $member->{'alias-name'}->__toString();
            }

        }

        return $retval;
    }

    public function storeAliasReference($name,$type) {
        $this->referencedBy[$type][] = $name;
        $this->refcount++;
    }

    private function verbosetextout($xmlfile) {

        $memberlist = $this->alias->{'alias-member-list'};

        for ($nr=0; $nr < count($memberlist->{'alias-member'}); $nr++) {

            $content = "";
            $member = $memberlist->{'alias-member'}[$nr];
            $type = $member->type;

            // prepare printf statement based on interface/address/alias/etc.
            switch ($type) {
                case 1:
                    if ($member->interface->__toString() != "Any") {
                        $typestring = "interface";
                        $value = $member->interface->__toString();
                    } else {
                        $typestring = "address";
                        $value = $member->address->__toString();
                        $content = $xmlfile->resolveAliasAddress($value);
                    }
                    break;
                case 2:
                    $typestring = "alias";
                    $value = $member->{'alias-name'};
                    break;
                default:
                    $value = "unknown type";
            }
            printf ("  %-02d  type:%-2d%-10s value: %s => %s\n", $nr, $type, $typestring, $value, $content);

            if ($value == "unknown type") {
                print_r($member);
            }
        }

        if ($this->refcount > 0) {

            print"\n  References: \n";

            foreach ($this->referencedBy as $type => $references) {

                foreach ($references as $reference) {
                    printf ("    %-15s %-50s\n", $type, $reference);
                }
            }
        }

        print "\n";
    }

    private function printAliasName($xmlfile) {
        global $options;

        if ($this->refcount == 0) {
            print $this->alias->name . " (unused)\n";
        } else {
            print $this->alias->name . "\n";
        }

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

    public function textout($xmlfile)
    {

        global $options;

        if ($this->aliastype != "interface"
            && $this->alias->name->__toString() != "dvcp_nets"
            && $this->alias->name->__toString() != "Any"
        ) {
            if ($this->refcount == 0) {

                $this->printAliasName($xmlfile);

            } else {

                if (!isset( $options["unused"] )) {
                    $this->printAliasName($xmlfile);
                }

            }
        }
    }

}

