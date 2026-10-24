/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// // import "androguard"

// rule Android_Dogspectus (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "Jacob Soo Lead Re" (Disabled: vacuous condition without evaluatable strings/modules)
// 		date = "20-July-2016" (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "This rule try to detects Dogspectus" (Disabled: vacuous condition without evaluatable strings/modules)
// 		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.activity(/PanickedActivity/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.INTERNET/i) and (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.WAKE_LOCK/i) (Disabled by Oshoosi Hardener)
// } (Disabled: vacuous condition without evaluatable strings/modules)
