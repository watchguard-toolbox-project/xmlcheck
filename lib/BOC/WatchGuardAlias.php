<?php
/**
 * Alias object class.
 *
 * @author Werner Maier (wm@boc.de)
 * @copyright 2019 BOC IT-Security GmbH
 */
namespace BOC;

use SimpleXMLElement;

/**
 * Class WatchGuardAlias
 * @package BOC
 */
class WatchGuardAlias extends WatchGuardObject
{
    /**
     * @var string
     */
    protected $type;

    /**
     * WatchGuardAlias constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element)
    {
        parent::__construct($element);
        $members = $this->obj->{'alias-member-list'}->{'alias-member'};
        if (count($members) == 1) {
            // only one member, check for interface...
            $member = $members[0];
            $type = $member->type;

            if ($type == 1 && $member->interface->__toString() != "Any") {
                $this->type = "interface";
            } else {
                $this->type = "other";
            }
        }
    }

    /**
     * @return array of referencedAlias->__toString();
     */
    public function getReferencedAliases() {

        $retval = [];

        $object=$this->obj;
        $memberlist = $object->{'alias-member-list'};

        for ($nr=0; $nr < count($memberlist->{'alias-member'}); $nr++) {

            $member = $memberlist->{'alias-member'}[$nr];

            // see only aliases, type==2
            if ($member->type == 2) {
                $retval[] = $member->{'alias-name'}->__toString();
            }

        }

        return $retval;
    }

    /**
     * @param WatchGuardXMLFile $xmlfile
     */
    protected function verbosetextout($xmlfile) {

        $nr = 0;
        $memberlist = $this->obj->{'alias-member-list'}->{'alias-member'};

        foreach ($memberlist as $member) {

            $content = "";
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

            $nr++;
        }

        parent::verbosetextout($xmlfile);

    }

    /**
     * @param WatchGuardXMLFile $xmlfile
     */
    public function textout($xmlfile)
    {

        global $options;

        if ($this->type != "interface"
            && $this->obj->name->__toString() != "dvcp_nets"
            && $this->obj->name->__toString() != "Any"
        ) {
            parent::textout($xmlfile);
        }
    }

}

