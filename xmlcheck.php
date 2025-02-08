#!/usr/bin/php
<?php
/**
 * xmlcheck.php - cli tool for checking watchguard xml configuration files
 *
 * commandline tool for checking watchguard xml configuration files
 * initial idea has been to check for unused aliases
 *
 */

use BOC\WatchGuardXMLFile;


$xmlfile = ""; // will be delivered by options.php

/** @noinspection PhpIncludeInspection */
require_once(dirname(__FILE__) . '/vendor/autoload.php');

require_once("lib/functions.php");

$options = [];
require_once("lib/options.php");

// global variables from options.php:
// $options
// $xmlfile

$policyxml = new WatchGuardXMLFile($xmlfile);

if (isset($options["simplexmlout"])) {
    print_r($policyxml);
    exit;
}

if (isset($options["listaliases"])) {
    $policyxml->listAllAliases();
}

if (isset($options["listnats"])) {
    $policyxml->listAllNats();
}

if (isset($options["listtags"])) {
    $policyxml->listAllTags();
}

if (isset($options["listpolicies"])) {
    $policyxml->findAliasReferences();

    if (isset($filtertag) && is_array($filtertag)) {
        $policyxml->setPolicyTagFilter($filtertag);
    }
    if (isset($filtertype) && is_array($filtertype)) {
        $policyxml->setPolicyTypeFilter($filtertype);
    }
    if (isset($filterexcludetype) && is_array($filterexcludetype)) {
        $policyxml->setPolicyExcludeTypeFilter($filterexcludetype);
    }
    if (isset($filterfrom) && is_array($filterfrom)) {
        $policyxml->setPolicyFromFilter($filterfrom);
    }
    if (isset($filterto) && is_array($filterto)) {
        $policyxml->setPolicyToFilter($filterto);
    }
    if (isset($filtername) && is_array($filtername)) {
        $policyxml->setPolicyNameFilter($filtername);
    }
    if (isset($filterexcludename) && is_array($filterexcludename)) {
        $policyxml->setPolicyExcludeNameFilter($filterexcludename);
    }
    if (isset($filteraction)) {
        $policyxml->setPolicyActionFilter($filteraction);
    }
    $policyxml->listAllPolicies();
}

if (isset($options["listservices"])) {
    if (isset($filtertype) && is_array($filtertype)) {
        $policyxml->setPolicyTypeFilter($filtertype);
    }
    if (isset($filterport) && is_array($filterport)) {
        $policyxml->setTypePortFilter($filterport);
    }
    if (isset($filterexcludetype) && is_array($filterexcludetype)) {
        $policyxml->setPolicyExcludeTypeFilter($filterexcludetype);
    }
    $policyxml->listAllServices();
}

if (isset($options["listtunnels"])) {
    $policyxml->listAllTunnels();
}

if (isset($options["alias"]) || isset($options["a"])) {
    foreach ($printaliases as $printalias) {
        print "\n";
        $policyxml->printAlias($printalias);
        print "\n";
    }
}

if (isset($options["info"])) {
    $format='text';
    if (isset($options['json'])) {
        $format = 'json';
    }
    if (isset($options['json-pretty'])) {
        $format = 'json-pretty';
    }
    $policyxml->printInfo($format);
    $policyxml->printJsonOutput($options);
}

if (isset($options['fwcheck'])) {
    $options["json"] = true;
    $policyxml->printInfo('prepare');

    $options["disabled"] = true;
    $policyxml->prepareAllPolicies('disabled_policies','Disabled Policies');

    unset($options["disabled"]);
    $policyxml->prepareAllPolicies('policies','Policies');

    $policyxml->listAllTags();

    $policyxml->listAllAliases();

    $policyxml->listAllServices();

    $policyxml->setPolicyNameFilter(array('/TEMP/'));
    $policyxml->prepareAllPolicies('temp_policies','Temp Policies (matched by name)');

    $policyxml->setPolicyNameFilter(array('/XXX/'));
    $policyxml->prepareAllPolicies('xxx_policies','XXX Policies (matched by name)');

    $policyxml->setPolicyNameFilter(array('/BAD/'));
    $policyxml->prepareAllPolicies('bad_policies','BAD Policies (matched by name)');

    $policyxml->setPolicyNameFilter(array('/VERY_BAD/'));
    $policyxml->prepareAllPolicies('very_bad_policies','VERY BAD Policies (matched by name)');

    // clear name filter
    $policyxml->setPolicyNameFilter(array());

    $policyxml->setPolicyActionFilter('Deny');
    $policyxml->prepareAllPolicies('deny_policies','Deny Policies (action=Deny)');

    $options['json'] = true;
    $policyxml->printJsonOutput($options);
}

if (isset($options["warnings"])) {
    $policyxml->printWarnings();
}
