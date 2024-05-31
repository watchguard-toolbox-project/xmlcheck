<?php
/**
 * Base class of WatchGuardXMLfile objects
 *
 * @author Werner Maier (wm@boc.de)
 * @copyright 2019 BOC IT-Security GmbH, www.boc.de
 */

namespace BOC;

use SimpleXMLElement;

/**
 * Class WatchGuardObject
 * @package BOC
 */
class WatchGuardObject
{
    /**
     * @var SimpleXMLElement stored object
     */
    protected $obj;
    /**
     * @var array list of object names which reference this object.
     */
    protected $referencedBy;
    /**
     * @var int count of references to this object
     */
    protected $refcount;

    /**
     * @var property of this object (proberty value from xml file)
     */
    protected $property;
    protected $jsonObject = [];
    protected $objectType;

    /**
     * WatchGuardObject constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element, $type='unspecified')
    {
        $this->obj = $element;
        $this->referencedBy = [];
        $this->refcount = 0;
        $this->objectType = $type;

        if (isset($this->obj->property)) {
            $this->property = $this->obj->property->__toString();
        }
    }

    /**
     * stores a reference to this object.
     * @param $name string name of reference to store
     * @param $type string type of reference (policy|alias|...)
     */
    public function storeReference($name, $type) {
        $this->referencedBy[$type][] = $name;
        $this->refcount++;
    }

    /**
     * print the full content of $this
     * @param $xmlfile WatchGuardXMLFile in which other objects can be found
     */
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

    /**
     * print the name of $this
     * @param $xmlfile WatchGuardXMLFile in which other objects can be found
     */
    protected function printName($xmlfile) {
        global $options;

        $property="";
        if (isset($this->property)) {
            switch ($this->property) {
                case 32:
                    $property = '(Prop:' . $this->property . ":SNAT-ACTION?)";
                    break;
            }
        }
        if ($this->refcount == 0) {
            print $this->obj->name->__toString() . "$property (unused)\n";
        } else {
            print $this->obj->name->__toString() . "$property\n";
        }

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

    /**
     * print the content of $this
     * @param $xmlfile WatchGuardXMLFile in which other objects can be found
     */
    public function textout($xmlfile) {

        global $options;

        if ($this->refcount == 0) {

            $this->printName($xmlfile);

        } else {

            if (!isset( $options["unused"] )) {
                $this->printName($xmlfile);
            }

        }
    }

    /**
     * print object as debug output
     * @return void
     */
    public function debug(){
        print_r($this->obj);
    }

    public function prepareJson($xmlfile) {
        $property="";
        if (isset($this->property)) {
            switch ($this->property) {
                case 32:
                    $property = '(Prop:' . $this->property . ":SNAT-ACTION?)";
                    break;
            }
        }
        $key = $this->objectType;
        $info = '';
        if ($this->refcount == 0) {
            $key = $this->objectType.'_unused';
            $info = ' (unused)';
        }
        $this->jsonObject[$key][] = array ( 'name' => $this->obj->name->__toString() . "$property$info",
                                            'comment' => $this->obj->comment->__toString());
    }

    /**
     * @return mixed
     */
    public function getJsonObject()
    {
        return $this->jsonObject;
    }

}

