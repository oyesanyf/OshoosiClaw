/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// import "androguard" (Disabled by Oshoosi Hardener)



// rule trojan: pornClicker  (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end." (Disabled: vacuous condition without evaluatable strings/modules)
// 		sample = "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca" (Disabled: vacuous condition without evaluatable strings/modules)
//  		reference = "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social" (Disabled: vacuous condition without evaluatable strings/modules)
//     author = "Koodous Project" (Disabled: vacuous condition without evaluatable strings/modules)
//      (Disabled: vacuous condition without evaluatable strings/modules)
// 	strings: (Disabled: vacuous condition without evaluatable strings/modules)
// 		$a = "SELEN3333" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$b = "SELEN33" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$c = "SELEN333" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$api = "http://mayis24.4tubetv.xyz/dmr/ya" (Disabled: vacuous condition without evaluatable strings/modules)
// 		 (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		($a and $b and $c and $api) or androguard.url(/mayis24\.4tubetv\.xyz/) (Identifier fixed/disabled by Oshoosi Hardener)
// } (Disabled: vacuous condition without evaluatable strings/modules)
