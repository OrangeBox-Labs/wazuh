/*
 * ================================================================
 * OrangeBox - YARA WebShell Extended / Heuristic Detection
 * ================================================================
 *
 * Purpose:
 *   Secondary detections for suspicious JSP techniques that are useful
 *   for hunting but are intentionally separated from the Core rules.
 *
 * IMPORTANT:
 *   A match here means "suspicious", not automatically "confirmed
 *   malware". These rules should normally generate a lower-severity
 *   Wazuh event and should not be used as a reason to discard a file.
 *
 * Compatibility:
 *   YARA 3.11.
 *
 * ================================================================
 */

rule OrangeBox_JSP_Base64_Command_Execution
{
    meta:
        description = "OrangeBox - JSP command execution with Base64-obfuscated shell or parameters"
        severity = "high"
        family = "jsp-obfuscated-command-execution"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $runtime = "Runtime.getRuntime().exec" ascii nocase
        $base64 = "java.util.Base64" ascii nocase
        $decode = "getDecoder" ascii nocase

    condition:
        $jsp and $request and $runtime and $base64 and $decode
}


rule OrangeBox_JSP_Dynamic_Loading_Reflection
{
    meta:
        description = "OrangeBox - JSP dynamic class loading combined with Java reflection"
        severity = "high"
        family = "jsp-dynamic-loading"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $loader = "ClassLoader" ascii nocase
        $define = "defineClass" ascii nocase
        $reflect1 = "Class.forName" ascii nocase
        $reflect2 = ".getMethod(" ascii nocase

    condition:
        $jsp and $request and $loader and $define and
        ($reflect1 or $reflect2)
}


rule OrangeBox_JSP_Encoded_String_Reconstruction
{
    meta:
        description = "OrangeBox - JSP encoded string reconstruction using integer array and XOR"
        severity = "high"
        family = "jsp-obfuscation"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $array = "int[]" ascii
        $char = "(char)" ascii
        $xor = "^" ascii
        $classforname = "Class.forName" ascii nocase

    condition:
        $jsp and $request and $array and $char and $xor and $classforname
}


rule OrangeBox_JSP_ClassLoader_Bytecode_Heuristic
{
    meta:
        description = "OrangeBox - JSP suspicious dynamic bytecode loading heuristic"
        severity = "high"
        family = "jsp-dynamic-bytecode"

    strings:
        $loader = "ClassLoader" ascii nocase
        $define = "defineClass" ascii nocase
        $bytecode = "byte[]" ascii nocase
        $newinstance = "newInstance()" ascii nocase

    condition:
        $loader and $define and $bytecode and $newinstance
}
