#!/usr/bin/php
<?php

use BOC\WatchGuardXMLFile;

require_once (dirname(__FILE__) . '/vendor/autoload.php');

require_once("lib/functions.php");
require_once("lib/options.php");

// globale Variablen us options:
// $options
// $xmlfile

$policyxml = new BOC\WatchGuardXMLFile($xmlfile);

if (isset($options["listaliases"])) {
    $policyxml->listAllAliases();
}

if (isset($options["listpolicies"])) {
    $policyxml->listAllPolicies();
}
