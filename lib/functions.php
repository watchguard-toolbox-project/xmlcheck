<?php
/**
 * centrally needed functions.
 *
 * if needed. should be empty.
 *
 */

/**
 * this is to remove the phpdoc no-summary-found error.
 */
$dummy="";
unset($dummy);

function isPregValid($regexp) {
    $valid = true;
    if (@preg_match($regexp, "teststring") === false) {
        // regexp failed and is likely invalid
        $valid = false;
    }
    return $valid;
}
