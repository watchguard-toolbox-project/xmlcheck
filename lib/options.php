<?php
/**
 * options.php - defining cli params and parsing getopt array. helptext.
 *
 * also helptext is defined here.
 *
 * @author       Werner Maier <wm@boc.de>
 * @copyright    (C) 2019-2022 BOC IT-Security GmbH
 */

/**
 * Version
 */
    define("VERSION", "0.8");

$shortopts = "i:f:ha:vlpustEDIWV";
$longopts = array(
    "infile:",
    "file:",
    "listaliases",
    "listpolicies",
    "listservices",
    "listtype",
    "listtags",
    "list-aliases",
    "list-policies",
    "list-tunnels",
    "list-types",
    "list-tags",
    "list-nats",
    "filter-name:",
    "filter-type:",
    "filter-port:",
    "filter-port-mail",
    "filter-port-web",
    "filter-tag:",
    "filter-to:",
    "filter-from:",
    "filter-action:",
    "filter-exclude-type:",
    "filter-exclude-name:",
    "alias:",
    "help",
    "verbose",
    "unused",
    "simplexmlout",
    "enabled",
    "disabled",
    "info",
    "json",
    "json-pretty",
    "fwcheck",
    "warnings",
    "version",
);
$options = getopt($shortopts, $longopts);

/**
 * displays version
 *
 */
function displayVersion()
{
    print "\n\n    xmlcheck v" . VERSION . "\n\n";
}
// show help
/**
 * displays help text.
 *
 */
function displayHelp() {

    displayVersion();

    print "
    Usage: 
    ./xmlcheck.php args|commands

    -h, --help              this help file
    -i, --infile filename   inputfile filename
    -f, --file filename     inputfile filename

    commands:
    --alias aliasname     print alias aliasname
    --list-aliases        lists all aliases
    --list-policies       lists all policies
    --list-types          lists all services(policy types)
    --list-tags           lists all tags
    --list-nats           lists all nats
    --list-tunnels        lists all BOVPN (Gateway-)Tunnels
    --info                lists general info
    --warnings            lists warnings (differences to best practice)
    
    internal commands:
    --fwcheck             output full information 
                          used for communication with fwcheck     
        
    filters:
    these filters need --list-policy, may be used multiple times and together.
    --filter-name name            only show policies matching name (regexp)
    --filter-exclude-name name    only show policies not matching name (regexp)
    --filter-type type            only show policies matching type 
    --filter-exclude-type type    only show policies not matching type 
    --filter-to   alias           only show policies using alias in to
    --filter-from alias           only show policies using alias in from
    --filter-action action        only show policies using action (Deny|Allow|Proxy)
    --filter-tag tag              only show policies using tag
    
    these filters need --list-types, may be used multiple times and together.
    --filter-type type       only show types matching type
    --filter-port port       only show types using port (e.g. '25/tcp')
    
    special filters
    --filter-port-mail       only show policies having ports 
                               25/110/143/465/587/993/995 
    
    example: 
        --list-policies
        --filter-type HTTPS --filter-to Any-External \
        --filter-from Any-Trusted --filter-from Any-Optional
    will display policies
        of type HTTPS from (Any-Trusted or Any-Optional) to Any-External
            
    options:
    -v, --verbose           verbose output
    -E, --enabled           only show enabled policies (= skip disabled policies)
    -D, --disabled          only show disabled policies (= skip enabled policies)
    -N, --nospace           change spaces to dots in policy name output
    -u, --unused            only show unused (aliases/tags/etc.)
    --json                  currently only available with info - output in json format
    --json-pretty           same as --json, but uses JSON_PRETTY_PRINT
    
    debug:
    --simplexmlout          print SimpleXML structure 
                            as read from xmlfile
    \n";
}

/**
 * displays help text and exits.
 */
function displayHelpAndExit() {
    displayHelp();
    exit;
}

/**
 * displays help text and error string
 *
 * @param $error    string
 */
function displayError($error) {
    print "\nerror: $error\n\n";
}

/**
 * displays help text and error string
 *
 * @param $error    string
 */
function displayHelpAndError($error) {
    displayHelp();
    displayError($error);
    exit;
}

if (isset($options["help"]) || isset($options["h"]) || count($options) == 0) {
    displayHelpAndExit();
}

if (isset($options["version"]) || isset($options["V"])) {
    displayVersion();
    exit;
}

$optcount=0;
$myopts=[];

if (isset($options["list-types"]) || isset($options["s"])
    || isset($options["listservices"])  || isset($options["listtype"])) {
    $options["listservices"] = true;
    $optcount++;
    $myopts[]="--list-types";
}

if (isset($options["list-tags"]) || isset($options["listtags"]) || isset($options["t"])) {
    $options["listtags"] = true;
    $optcount++;
    $myopts[]="--list-tags";
}

if (isset($options["list-tunnels"])) {
    $options["listtunnels"] = true;
    $optcount++;
    $myopts[]="--list-tunnels";
}

if (isset($options["list-aliases"]) || isset($options["listaliases"]) || isset($options["l"])) {
    $options["listaliases"] = true;
    $optcount++;
    $myopts[]="--list-aliases";
}

if (isset($options["list-policies"]) || isset($options["listpolicies"]) || isset($options["p"])) {
    $options["listpolicies"] = true;
    $optcount++;
    $myopts[]="--list-policies";
}

if (isset($options["list-nats"])) {
    $options["listnats"] = true;
    $optcount++;
    $myopts[]="--list-nats";
}


if (isset($options["verbose"]) || isset($options["v"])) {
    $options["verbose"] = true;
    $optcount++;
    $myopts[]="--verbose";
}

if (isset($options["enabled"]) || isset($options["E"])) {
    $options["enabled"] = true;
    $optcount++;
    $myopts[]="--enabled";
}

if (isset($options["disabled"]) || isset($options["D"])) {
    $options["disabled"] = true;
    $optcount++;
    $myopts[]="--disabled";
}

if (isset($options["unused"]) || isset($options["u"])) {
    $options["unused"] = true;
    $optcount++;
    $myopts[]="--unused";
}

if (isset($options["info"]) || isset($options["I"])) {
    $options["info"] = true;
    $optcount++;
    $myopts[]="--info";
}

if (isset($options["warnings"]) || isset($options["W"])) {
    $options["warnings"] = true;
    $optcount++;
    $myopts[]="--warnings";
}

if (isset($options["filter-type"])) {
    $filtertype=[];
    if (is_array($options['filter-type'])) {
        $filtertype=$options['filter-type'];
        $optcount+= (2* count($filtertype));
    } else {
        $filtertype[]=$options['filter-type'];
        $optcount+=2;
    }
    foreach($filtertype as $filter) {
        $myopts[]="--filter-type";
        $myopts[]=$filter;
    }
    // workaround blank behaviour in BASH and VARIABLES
    for ($i=0; $i<count($filtertype); $i++) {
        $filtertype[$i]=preg_replace("/°/"," ", $filtertype[$i]);
    }
}

if (isset($options["filter-name"])) {
    $filtername=[];
    if (is_array($options['filter-name'])) {
        foreach ($options['filter-name'] as $filter) {
            if (isPregValid($filter)) {
                $filtername[]=$filter;
            } else {
                print " Error: '" . $filter . "' is not a valid regexp.\n";
                exit;
            }
        }
        $optcount+= (2* count($filtername));
    } else {
        if (isPregValid($options['filter-name'])) {
            $filtername[]=$options['filter-name'];
            $optcount+=2;
        } else {
            print " Error: '" . $options['filter-name'] . "' is not a valid regexp.\n";
            exit;
        }
    }
    foreach($filtername as $filter) {
        $myopts[]="--filter-name";
        $myopts[]=$filter;
    }
    // workaround blank behaviour in BASH and VARIABLES
    for ($i=0; $i<count($filtername); $i++) {
        $filtername[$i]=preg_replace("/°/"," ", $filtername[$i]);
    }
}

if (isset($options["filter-exclude-name"])) {
    $filterexcludename=[];
    if (is_array($options['filter-exclude-name'])) {
        foreach ($options['filter-exclude-name'] as $filter) {
            if (isPregValid($filter)) {
                $filterexcludename[]=$filter;
            } else {
                print " Error: '" . $filter . "' is not a valid regexp.\n";
                exit;
            }
        }
        $optcount+= (2* count($filterexcludename));
    } else {
        if (isPregValid($options['filter-exclude-name'])) {
            $filterexcludename[]=$options['filter-exclude-name'];
            $optcount+=2;
        } else {
            print " Error: '" . $options['filter-exclude-name'] . "' is not a valid regexp.\n";
            exit;
        }
    }
    foreach($filterexcludename as $filter) {
        $myopts[]="--filter-exclude-name";
        $myopts[]=$filter;
    }
    // workaround blank behaviour in BASH and VARIABLES
    for ($i=0; $i<count($filterexcludename); $i++) {
        $filterexcludename[$i]=preg_replace("/°/"," ", $filterexcludename[$i]);
    }
}


if (isset($options["filter-tag"])) {
    $filtertag=[];
    if (is_array($options['filter-tag'])) {
        $filtertag=$options['filter-tag'];
        $optcount+= (2* count($filtertag));
    } else {
        $filtertag[]=$options['filter-tag'];
        $optcount+=2;
    }
    foreach($filtertag as $filter) {
        $myopts[]="--filter-tag";
        $myopts[]=$filter;
    }
}

if (isset($options["filter-exclude-type"])) {
    $filterexcludetype=[];
    if (is_array($options['filter-exclude-type'])) {
        $filterexcludetype=$options['filter-exclude-type'];
        $optcount+= (2* count($filterexcludetype));
    } else {
        $filterexcludetype[]=$options['filter-exclude-type'];
        $optcount+=2;
    }
    foreach($filterexcludetype as $filter) {
        $myopts[]="--filter-exclude-type";
        $myopts[]=$filter;
    }
}

if (isset($options["filter-port"])) {
    $filterport=[];
    if (is_array($options['filter-port'])) {
        $filterport=$options['filter-port'];
        $optcount+= (2* count($filterport));
    } else {
        $filterport[]=$options['filter-port'];
        $optcount+=2;
    }
    foreach($filterport as $filter) {
        $myopts[]="--filter-port";
        $myopts[]=$filter;
    }
}

function filterPort($type) {
    global $myopts;
    global $filterport;

    if (!is_array($filterport)) {
        $filterport=[];
    }

    switch ($type) {
        case "mail":
            $filterport[]="25/tcp";
            $filterport[]="110/tcp";
            $filterport[]="143/tcp";
            $filterport[]="465/tcp";
            $filterport[]="587/tcp";
            $filterport[]="993/tcp";
            $filterport[]="995/tcp";
            break;
        case "web":
            $filterport[]="80/tcp";
            $filterport[]="443/tcp";
            $filterport[]="443/udp";
            break;
    }

    foreach($filterport as $filter) {
        $myopts[]="--filter-port";
        $myopts[]=$filter;
    }
}

if (isset($options["filter-port-mail"])) {
    filterPort("mail");
    $optcount++;
}

if (isset($options["filter-port-web"])) {
    filterPort("web");
    $optcount++;
}

if (isset($options["filter-from"])) {
    $filterfrom=[];
    if (is_array($options['filter-from'])) {
        $filterfrom=$options['filter-from'];
        $optcount+= 2* count($filterfrom);
    } else {
        $filterfrom[]=$options['filter-from'];
        $optcount+=2;
    }
    foreach($filterfrom as $filter) {
        $myopts[]="--filter-from";
        $myopts[]=$filter;
    }
}
if (isset($options["filter-to"])) {
    $filterto=[];
    if (is_array($options['filter-to'])) {
        $filterto=$options['filter-to'];
        $optcount+= 2* count($filterto);
    } else {
        $filterto[]=$options['filter-to'];
        $optcount+=2;
    }
    foreach($filterto as $filter) {
        $myopts[]="--filter-to";
        $myopts[]=$filter;
    }
}
if (isset($options["alias"]) || isset($options["a"])) {
    $printalias = isset($options["alias"]) ? $options["alias"] : $options["a"];
    if (is_array($printalias)) {
        $printaliases = $printalias;
        $optcount+= 2* count($printaliases);
    } else {
        $printaliases = [];
        $printaliases[] = $printalias;
        $optcount+=2;
    }
    foreach($printaliases as $alias) {
        $myopts[]="--alias";
        $myopts[]=$alias;
    }
}

if (isset($options["filter-action"])) {
    if (is_array($options['filter-action'])) {
        displayError("filter-action may only be used once.");
        exit;
    } else {
        if (in_array($options['filter-action'], [ 'Allow', 'Deny', 'Proxy' ])) {
            $filteraction=$options['filter-action'];
            $optcount+=2;
        } else {
            displayError("filter-action may only be one of Deny|Allow|Proxy.");
            exit;
        }
    }
}

if (isset($options["json"])) {
    $options["json"] = true;
    $optcount++;
    $myopts[]="--json";
}

if (isset($options["json-pretty"])) {
    $options["json"] = true;
    $options["json-pretty"] = true;
    $optcount++;
    $myopts[]="--json-pretty";
}

if (isset($options["fwcheck"])) {
    $options["fwcheck"] = true;
    $optcount++;
    $myopts[]="--fwcheck";
}

$xmlfile = "";
if (   isset($options["infile"]) || isset($options["i"])
    || isset($options["file"]) || isset($options["f"])    ) {

    if (isset($options["i"])) $xmlfile = $options["i"];
    if (isset($options["infile"])) $xmlfile = $options["infile"];
    if (isset($options["f"])) $xmlfile = $options["f"];
    if (isset($options["file"])) $xmlfile = $options["file"];

    if (is_array($xmlfile)) {
        displayHelpAndError("-i accepts only ONE file argument.");
        print "hint: problem might be with this option: '" . $xmlfile[1] .
              "'.\n      is it a valid option/action/argument?\n\n";
        exit;
    }
    if (!is_file($xmlfile)) {
        displayHelpAndError("file '$xmlfile' not found.");
        exit;
    }
    $optcount+=2;
    $myopts[]="--file";
    $myopts[]=$xmlfile;
}


if ($xmlfile === "") {
    displayHelpAndError("no input file.");
    exit;
}

if (isset($filtertag) && is_array($filtertag) && !isset($options['listpolicies']) && !isset($options['listtags'])) {
    displayError("--filter-tag needs --list-policies or --list-tags");
    exit;
}
if (isset($filtertype) && is_array($filtertype) && !isset($options['listpolicies']) && !isset($options['listservices'])) {
    displayError("--filter-type needs --list-policies or --list-types");
    exit;
}
if (isset($filterport) && is_array($filterport) && !isset($options['listservices'])) {
    displayError("--filter-port needs --list-types");
    exit;
}
if ((isset($filtername) && is_array($filtername)) &&
    !(isset($options['listpolicies']) || isset($options['listservices']) || isset($options['fwcheck']))) {
    displayError("--filter-name needs --list-policies, --list-type or --fwcheck");
    exit;
}
// check if too much actions:
$actions = 0;
if (isset($options['listservices']) || isset($options['listtype'])) $actions++;
if (isset($options['listpolicies'])) $actions++;
if (isset($options['listtags'])) $actions++;
if (isset($options['listnats'])) $actions++;
if (isset($options['listaliases'])) $actions++;
if (isset($options['listtunnels'])) $actions++;
if (isset($options['info'])) $actions++;
if (isset($options['fwcheck'])) $actions++;
if (isset($options['warnings'])) $actions++;

if ($actions>1) {
    displayError("only 1 (one) action may be used.");
    exit;
}

// sanity check if all options have been read.

if (count($argv) != $optcount +1 ) {
    displayError("at least on option has not been recognized by getopt.");
    $opts=$argv;
    for ($var=0; $var<=$optcount; $var++) {
        array_shift($opts);
    }
    print "error supposed to be in: " . $opts[0] . "\n\n";

    print "\nall arguments:\n";
    array_shift($argv);
    print_r($argv);
    print "\nparsed arguments:\n";
    print_r($myopts);
    print "\nunparsed arguments:\n";
    print_r($opts);
    print "\n";
    exit;
}