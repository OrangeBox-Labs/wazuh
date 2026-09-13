/*
 * OrangeBox YARA entry point
 *
 * Keep Core and Extended rules separate so that production policy can
 * decide which classes of detection are allowed to generate critical
 * alerts or email.
 */

include "orangebox-webshell-core.yar"
include "orangebox-webshell-extended.yar"
