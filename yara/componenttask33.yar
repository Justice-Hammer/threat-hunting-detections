/*
 * "ComponentTask33" — YARA rule set
 * TLP:CLEAR  ·  author: Justice Hammer  ·  date: 2026-08-28
 *
 * Rules: config-store/build metadata, agent source,
 * builder residue — plus one optional low-priority rule for the .NET helpers.
 *
 * DESIGN NOTE (F1): the config XOR key == install-meta.json "buildSeed" and
 * ROTATES PER BUILD. No rule here hardcodes the byte value c8c384083f; the
 * config rule anchors on the "buildSeed" KEY NAME and the surrounding JSON shape.
 */

rule ComponentTask33_BuildMeta_ConfigStore : componenttask33 config
{
    meta:
        description  = "ComponentTask33 install-meta.json — build/scatter descriptor (buildSeed key + configStore + scatter parts). Key-name anchored, NOT the rotating key value."
        author       = "Justice Hammer"
        date         = "2026-08-28"
        tlp          = "CLEAR"
        reference    = "https://github.com/Justice-Hammer/threat-hunting-detections"
        mitre_attack = "T1564, T1027"
        fidelity     = "HIGH — the co-occurrence of buildSeed + configStore + a base/parts scatter block is unique to this builder"

    strings:
        $seed      = "\"buildSeed\""        ascii
        $store     = "\"configStore\""      ascii
        $scatt     = "\"scatterScript\""    ascii
        $parts     = "\"parts\""            ascii
        $base_l    = "\"LocalAppData\""     ascii
        $base_r    = "\"RoamingAppData\""   ascii
        $cfgname   = "HiddenVirtualSilentLoader" ascii

    condition:
        filesize < 16KB and $seed and $store and
        ( $scatt or ($parts and ($base_l or $base_r)) or $cfgname )
}

rule ComponentTask33_AgentSource : componenttask33 agent
{
    meta:
        description  = "ComponentTask33 Node agent source (win-agent-client) — command dispatch opcodes + WS protocol + on-chain discovery selector. Survives repacking; dies on minify."
        author       = "Justice Hammer"
        date         = "2026-08-28"
        tlp          = "CLEAR"
        reference    = "https://github.com/Justice-Hammer/threat-hunting-detections"
        mitre_attack = "T1059.007, T1071.001, T1102"
        fidelity     = "HIGH — opcode cluster / protocol cluster / discovery selector are each near-zero FP"

    strings:
        $pkg    = "win-agent-client"         ascii

        // command dispatch opcodes (commands.js switch) — cluster is unique
        $op1    = "download_run"             ascii
        $op2    = "wallet_scan"              ascii
        $op3    = "agent_update"             ascii
        $op4    = "load_script"              ascii

        // WebSocket protocol / remote-script cluster (index.js, remoteScript.js)
        $pr1    = "X-Agent-Token"            ascii
        $pr2    = "command_result"           ascii
        $pr3    = "wallet_report"            ascii
        $pr4    = "/api/agent/script"        ascii
        $pr5    = "remote-agent-script.js"   ascii

        // EtherHiding on-chain C2 discovery (contractDiscovery.js)
        $disc1  = "contractDiscovery"        ascii
        $disc2  = "0x4ab7874e"               ascii   /* getPanelUrl() selector */

    condition:
        filesize < 128KB and (
            $pkg
            or 4 of ($op*)
            or (2 of ($op*) and 1 of ($pr*))
            or 3 of ($pr*)
            or all of ($disc*)
        )
}

rule ComponentTask33_BuilderResidue : componenttask33 builder
{
    meta:
        description  = "ComponentTask33 builder-kit residue — default token, builder script, dead launcherCmd. For retrohunting OTHER builds of the kit, not victim triage."
        author       = "Justice Hammer"
        date         = "2026-08-28"
        tlp          = "CLEAR"
        reference    = "https://github.com/Justice-Hammer/threat-hunting-detections"
        mitre_attack = "T1587.001"
        fidelity     = "MEDIUM — retrohunt anchor; any single string is weak, combine or triage hits"

    strings:
        $tok    = "change-me-to-secret-token"        ascii
        $bld    = "build-client.ps1"                 ascii
        $cmd    = "MonitorExtensionStreamLoader.cmd"  ascii

    condition:
        filesize < 64KB and any of them
}

rule ComponentTask33_DotNetHelpers : componenttask33 tools
{
    meta:
        description  = "ComponentTask33 native .NET helpers — launcher (WinAgent.exe) / screenshot (CaptureScreen.exe) by embedded internal name. LOW priority; on-disk name rotates, prefer pinning the MVID."
        author       = "Justice Hammer"
        date         = "2026-08-28"
        tlp          = "CLEAR"
        reference    = "https://github.com/Justice-Hammer/threat-hunting-detections"
        mitre_attack = "T1113"
        fidelity     = "LOW-MEDIUM — generic C# stubs; require internal name + tiny managed PE to bound FP"

    strings:
        $mz       = { 4D 5A }
        $dotnet   = "_CorExeMain" ascii
        $in_cap   = "CaptureScreen.exe" wide
        $usage    = "Usage: CaptureScreen.exe <output.png>" wide
        $in_launch= "WinAgent.exe" wide
        $node     = "node.exe" wide
        $uninst   = "--uninstall" wide

    condition:
        $mz at 0 and $dotnet and filesize < 16KB and (
            ($in_cap and $usage) or
            ($in_launch and $node and $uninst)
        )
}
