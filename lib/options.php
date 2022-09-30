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
    define("VERSION", "0.4");

$shortopts = "i:f:ha:vlpustEDIW";
$longopts = array(
    "infile:",
    "file:",
    "listaliases",
    "listpolicies",
    "listservices",
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
);
$options = getopt($shortopts, $longopts);

// show help
/**
 * displays help text.
 *
 */
function displayHelp() {
    print "
    
    xmlcheck v" . VERSION . "
    
    Usage: 
    ./xmlcheck.php args|commands

    -h, --help              this help file
    -i, --infile filename   inputfile filename

    commands:
    -a aliasname, 
      --alias aliasname     print alias aliasname
    -l, --listaliases       lists all aliases
    -p, --listpolicies      lists all policies
    -s, --listservices      lists all services
    -t, --listtags          lists all tags
    -I, --info              lists general info
    -W, --warnings          lists warnings (differences to best practice)
        
    options:
    -v, --verbose           verbose output
    -E, --enabled           only show enabled policies (= skip disabled policies)
    -D, --disabled          only show disabled policies (= skip enabled policies)
    -N, --nospace           change spaces to dots in policy name output
    
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
function displayHelpAndError($error) {
    displayHelp();
    print "\nerror: $error\n\n";
}

if (isset($options["help"]) || isset($options["h"]) || count($options) == 0) {
    displayHelpAndExit();
}

if (isset($options["listservices"]) || isset($options["s"])) {
    $options["listservices"] = true;
}

if (isset($options["listtags"]) || isset($options["t"])) {
    $options["listtags"] = true;
}

if (isset($options["listaliases"]) || isset($options["l"])) {
    $options["listaliases"] = true;
}

if (isset($options["listpolicies"]) || isset($options["p"])) {
    $options["listpolicies"] = true;
}

if (isset($options["verbose"]) || isset($options["v"])) {
    $options["verbose"] = true;
}

if (isset($options["enabled"]) || isset($options["E"])) {
    $options["enabled"] = true;
}

if (isset($options["disabled"]) || isset($options["D"])) {
    $options["disabled"] = true;
}

if (isset($options["unused"]) || isset($options["u"])) {
    $options["unused"] = true;
}

if (isset($options["info"]) || isset($options["I"])) {
    $options["info"] = true;
}

if (isset($options["warnings"]) || isset($options["W"])) {
    $options["warnings"] = true;
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
}

if ($xmlfile === "") {
    displayHelpAndError("no input file.");
    exit;
}

