/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and 
    open to any user or organization, as long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.
	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

// // import "androguard"

// rule backdoor: dropper (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "Antonio Sanchez <asanchez@koodous.com>" (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "This rule detects fake samples with a backdoor/dropper" (Disabled: vacuous condition without evaluatable strings/modules)
// 		sample = "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539" (Disabled: vacuous condition without evaluatable strings/modules)
// 		source = "https://koodous.com/rulesets/1765" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.url("http://sys.wksnkys7.com")  (Disabled by Oshoosi Hardener)
// 		or androguard.url("http://sys.hdyfhpoi.com")  (Disabled by Oshoosi Hardener)
// 		or androguard.url("http://sys.syllyq1n.com")  (Disabled by Oshoosi Hardener)
// 		or androguard.url("http://sys.aedxdrcb.com") (Disabled by Oshoosi Hardener)
// 		or androguard.url("http://sys.aedxdrcb.com") (Disabled by Oshoosi Hardener)
// } (Disabled: vacuous condition without evaluatable strings/modules)
