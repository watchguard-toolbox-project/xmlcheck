<?php
/**
 * Nat object class.
 *
 * @author Werner Maier (wm@boc.de)
 * @copyright 2023 BOC IT-Security GmbH
 */
namespace BOC;

use SimpleXMLElement;

/**
 * Class WatchGuardNat
 * @package BOC
 */
class WatchGuardNat extends WatchGuardObject
{
    /**
     * type of Nat: dyn, 1-to-1, SNAT, etc.
     * @var string
     */
    protected $type;

    /**
     * WatchGuardNat constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element)
    {
        parent::__construct($element);
        $members = $this->obj->{'nat-item'}->{'member'};
        if (count($members) == 1) {
            // only one member, check for interface...
            $member = $members[0];
        }
    }

    /**
     * verbose output of alias contents.
     * overloads base class method
     * @param WatchGuardXMLFile $xmlfile
     */
    protected function verbosetextout($xmlfile) {

        $nr = 0;
        $memberlist = $this->obj->{'nat-item'}->{'member'};

        // if (is_array($memberlist))
        foreach ($memberlist as $member) {

            $content = "";
            $type = $member->{'addr-type'}->__toString();

            // prepare printf statement based on type etc.
            switch ($type) {
                case 4:
                    $port = $member->{'port'}->__toString();
                    $ext = $member->{'ext-addr-name'}->__toString();
                    $ifc = $member->{'interface'}->__toString();
                    $int = $member->{'addr-name'}->__toString();
                    $typestring="SNAT";
                    printf ("  %-02d  t:%-2d%-10s  %s(%s) => %s : %s\n", $nr, $type, $typestring, $ext, $ifc, $int, $port);
                    break;
                case 1:
                    $ip = '';
                    $typestring="DNAT";
                    $addrtype = $member->{'addr-type'}->__toString();
                    if ($addrtype == 1) {
                        $ip = $member->{'ip'}->__toString();
                    }
                    printf ("  %-02d  t:%-2d%-10s  %s(%s)\n", $nr, $type, $typestring, $ip, $addrtype);
                    break;
                default:
                    $typestring="unknown type";
            }


            if ($typestring == "unknown type") {
                print_r($member);
            }

            $nr++;
        }

        parent::verbosetextout($xmlfile);

    }

    /**
     * output for alias objects, suppressing some defaults
     * overloads base class method
     *
     * @param WatchGuardXMLFile $xmlfile
     */
    public function textout($xmlfile)
    {

        parent::textout($xmlfile);
    }

}

