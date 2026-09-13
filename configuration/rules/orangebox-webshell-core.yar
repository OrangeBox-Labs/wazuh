/*
 * ================================================================
 * OrangeBox - YARA WebShell Core Detection
 * ================================================================
 *
 * Purpose:
 *   High-confidence detection of JSP webshell families observed in
 *   real compromised Zimbra/Carbonio environments.
 *
 * Design:
 *   These rules detect combinations of behaviors, not isolated words.
 *   A YARA miss MUST NOT be interpreted as evidence that a file is
 *   benign. YARA is only one source of evidence in the Wazuh pipeline.
 *
 * Compatibility:
 *   Written for YARA 3.11 compatibility. No newer modules/features
 *   are intentionally required.
 *
 * Families covered:
 *   1. JSP command execution through Runtime.exec()
 *   2. JSP command execution through ProcessBuilder + shell
 *   3. JSP dynamic ClassLoader / defineClass loaders
 *   4. JSP ClassLoader loaders using Base64 decoding
 *   5. JSP encrypted ClassLoader loaders using AES/Cipher
 *   6. JSP dynamic ClassLoader with XOR-style obfuscation
 *
 * ================================================================
 */

rule OrangeBox_JSP_Runtime_Command_Execution
{
    meta:
        description = "OrangeBox - JSP webshell executing HTTP parameter through Runtime.exec"
        severity = "critical"
        family = "jsp-command-execution"
        reference = "OrangeBox real-world JSP samples"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $runtime = "Runtime.getRuntime().exec" ascii nocase

    condition:
        $jsp and $request and $runtime
}


rule OrangeBox_JSP_ProcessBuilder_Shell
{
    meta:
        description = "OrangeBox - JSP webshell executing HTTP parameter through ProcessBuilder shell"
        severity = "critical"
        family = "jsp-command-execution"
        reference = "OrangeBox real-world JSP samples"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $process = "ProcessBuilder" ascii nocase
        $shell1 = "/bin/sh" ascii
        $shell2 = "bash" ascii nocase
        $shell3 = "-c" ascii

    condition:
        $jsp and $request and $process and ($shell1 or $shell2) and $shell3
}


rule OrangeBox_JSP_Dynamic_ClassLoader
{
    meta:
        description = "OrangeBox - JSP dynamic bytecode loader using ClassLoader and defineClass"
        severity = "critical"
        family = "jsp-dynamic-classloader"
        reference = "OrangeBox real-world JSP samples"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $loader = "ClassLoader" ascii nocase
        $define = "defineClass" ascii nocase

    condition:
        $jsp and $request and $loader and $define
}


rule OrangeBox_JSP_ClassLoader_Base64
{
    meta:
        description = "OrangeBox - JSP dynamic ClassLoader with Base64 payload decoding"
        severity = "critical"
        family = "jsp-dynamic-classloader"
        reference = "OrangeBox real-world JSP samples"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $loader = "ClassLoader" ascii nocase
        $define = "defineClass" ascii nocase
        $base64a = "BASE64Decoder" ascii nocase
        $base64b = "java.util.Base64" ascii nocase
        $decode1 = "decodeBuffer" ascii nocase
        $decode2 = "getDecoder" ascii nocase

    condition:
        $jsp and $request and $loader and $define and
        (($base64a and $decode1) or ($base64b and $decode2))
}


rule OrangeBox_JSP_Encrypted_ClassLoader_AES
{
    meta:
        description = "OrangeBox - JSP encrypted ClassLoader loader using AES and Base64"
        severity = "critical"
        family = "jsp-encrypted-loader"
        reference = "OrangeBox real-world JSP samples"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $loader = "ClassLoader" ascii nocase
        $define = "defineClass" ascii nocase
        $cipher = "Cipher.getInstance" ascii nocase
        $aes = "AES" ascii
        $key = "SecretKeySpec" ascii nocase
        $base64 = "base64Decode" ascii nocase

    condition:
        $jsp and $request and $loader and $define and
        $cipher and $aes and $key and $base64
}


rule OrangeBox_JSP_Obfuscated_Dynamic_ClassLoader
{
    meta:
        description = "OrangeBox - JSP obfuscated dynamic ClassLoader with XOR string reconstruction"
        severity = "critical"
        family = "jsp-obfuscated-loader"
        reference = "OrangeBox real-world JSP samples"

    strings:
        $jsp = "<%" ascii
        $request = "request.getParameter" ascii nocase
        $loader = "ClassLoader" ascii nocase
        $define = "defineClass" ascii nocase
        $xor = "^ 16" ascii
        $int_array = "int[]" ascii

    condition:
        $jsp and $request and $loader and $define and $xor and $int_array
}
