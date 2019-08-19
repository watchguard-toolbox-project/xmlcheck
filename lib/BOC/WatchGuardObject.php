<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardObject
{
    protected $obj;
    protected $referencedBy;
    protected $refcount;

    public function __construct(SimpleXMLElement $element)
    {
        $this->obj = $element;
        $this->referencedBy = [];
        $this->refcount = 0;
    }

    public function storeReference($name,$type) {
        $this->referencedBy[$type][] = $name;
        $this->refcount++;
    }

    protected function verbosetextout($xmlfile) {

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

    protected function printName($xmlfile) {
        global $options;

        if ($this->refcount == 0) {
            print $this->obj->name->__toString() . " (unused)\n";
        } else {
            print $this->obj->name->__toString() . "\n";
        }

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

    public function textout($xmlfile)
    {

        global $options;

        if ($this->refcount == 0) {

            $this->printName($xmlfile);

        } else {

            if (!isset( $options["unused"] )) {
                $this->printName($xmlfile);
            }

        }
    }

}

