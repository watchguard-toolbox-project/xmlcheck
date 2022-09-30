<?php
/**
 * options.php - defining cli params and parsing getopt array. helptext.
 *
 * also helptext is defined here.
 *
 * @author       Werner Maier <wm@boc.de>
 * @copyright    (C) 2019 BOC IT-Security GmbH
 */

/**
 * Version
 */
    define("VERSION", "0.5");

$shortopts = "i:f:ha:vlpustEDIWV";
$longopts = array(
    "infile:",
    "file:",
    "listaliases",
    "listpolicies",
    "listservices",
    "listtype",
    "filter-type:",
    "filter-to:",
    "filter-from:",
    "listtags",
    "alias:",
    "help",
    "verbose",
    "unused",
    "simplexmlout",
    "enabled",
    "disabled",
    "info",
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
    -a aliasname, 
      --alias aliasname     print alias aliasname
    -l, --listaliases       lists all aliases
    -p, --listpolicies      lists all policies
    -s, --listservices      lists all services
        --listtype          lists all services
    -t, --listtags          lists all tags
    -I, --info              lists general info
    -W, --warnings          lists warnings (differences to best practice)
        
    filters:
    these filters need --listtype, may be used multiple times and together.
    --filter-type type       only show policies having type 
    --filter-to   alias      only show policies using alias in to
    --filter-from alias      only show policies using alias in from
    example: 
        --listpolicies
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

if (isset($options["listservices"]) || isset($options["s"])
    || isset($options["listtype"])) {
    $options["listservices"] = true;
    $optcount++;
    $myopts[]="--list-type";
}

if (isset($options["listtags"]) || isset($options["t"])) {
    $options["listtags"] = true;
    $optcount++;
    $myopts[]="--list-tags";
}

if (isset($options["listaliases"]) || isset($options["l"])) {
    $options["--listaliases"] = true;
    $optcount++;
    $myopts[]="--list-aliases";
}

if (isset($options["listpolicies"]) || isset($options["p"])) {
    $options["listpolicies"] = true;
    $optcount++;
    $myopts[]="--list-policies";
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

if (isset($filtertype) && is_array($filtertype) && !isset($options['listpolicies'])) {
    displayError("--filter-type needs --listpolicies.");
    exit;
}
// check if too much actions:
$actions = 0;
if (isset($options['listservices']) || isset($options['listtype'])) $actions++;
if (isset($options['listpolicies'])) $actions++;
if (isset($options['listtags'])) $actions++;
if (isset($options['listaliases'])) $actions++;
if (isset($options['alias'])) $actions++;
if (isset($options['info'])) $actions++;
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