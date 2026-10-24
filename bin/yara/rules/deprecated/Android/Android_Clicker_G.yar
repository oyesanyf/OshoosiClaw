/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// import "androguard" (Disabled by Oshoosi Hardener)

// rule Android_Clicker_G (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "Jacob Soo Lead Re" (Disabled: vacuous condition without evaluatable strings/modules)
// 		date = "01-July-2016" (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "This rule try to detects Clicker.G samples" (Disabled: vacuous condition without evaluatable strings/modules)
// 		reference = "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/" (Disabled: vacuous condition without evaluatable strings/modules)
// 	strings: (Disabled: vacuous condition without evaluatable strings/modules)
// 		$a = "upd.php?text=" (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.receiver(/MyBroadCastReceiver/i) and $a (Identifier fixed/disabled by Oshoosi Hardener)
// } (Disabled: vacuous condition without evaluatable strings/modules)
