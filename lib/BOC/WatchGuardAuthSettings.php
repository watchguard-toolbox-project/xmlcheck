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
class WatchGuardAuthSettings extends WatchGuardObject
{
    /**
     * color of Tag
     * @var string
     */
    protected $bruteForceProtectionEnabled;
    protected $bruteForceProtectionFailures;
    protected $bruteForceProtectionPeriod;
    protected $bruteForceProtectionDuration;

    /**
     * WatchGuardTag constructor.
     * @param SimpleXMLElement $xmlfile
     */
    public function __construct(SimpleXMLElement $xmlfile)
    {
        parent::__construct($xmlfile->{'system-parameters'}->{'auth-global-setting'});
        $this->bruteForceProtectionEnabled = "0";
        $this->bruteForceProtectionFailures = "0";
        $this->bruteForceProtectionPeriod = "0";
        $this->bruteForceProtectionDuration = "0";
        if (isset($this->obj->{'brute-force-protection'}->{'enabled'})
            && ($this->obj->{'brute-force-protection'}->{'enabled'}->__toString() == "1")) {
            $this->bruteForceProtectionEnabled = "1";
            $this->bruteForceProtectionFailures = $this->obj->{'brute-force-protection'}->{'failures'}->__toString();
            $this->bruteForceProtectionPeriod = $this->obj->{'brute-force-protection'}->{'period'}->__toString();
            $this->bruteForceProtectionDuration = $this->obj->{'brute-force-protection'}->{'duration'}->__toString();
        };
    }

    public function getBruteForceProtectionEnabled(): string
    {
        return $this->bruteForceProtectionEnabled;
    }

    public function getBruteForceProtectionFailures(): string
    {
        return $this->bruteForceProtectionFailures;
    }

    public function getBruteForceProtectionPeriod(): string
    {
        return $this->bruteForceProtectionPeriod;
    }

    public function getBruteForceProtectionDuration(): string
    {
        return $this->bruteForceProtectionDuration;
    }

}
