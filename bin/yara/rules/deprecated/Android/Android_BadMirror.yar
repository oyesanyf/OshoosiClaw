/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// import "androguard" (Disabled by Oshoosi Hardener)

// rule Android_BadMirror (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "Jacob Soo Lead Re" (Disabled: vacuous condition without evaluatable strings/modules)
// 		date = "06-June-2016" (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \"app\" (download an APK) or \"page\" (display a given URL)." (Disabled: vacuous condition without evaluatable strings/modules)
// 		source = "https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.service(/SimInsService/i) and (Identifier fixed/disabled by Oshoosi Hardener)
//         androguard.permission(/android.permission.READ_PHONE_STATE/i) (Identifier fixed/disabled by Oshoosi Hardener)
// } (Disabled: vacuous condition without evaluatable strings/modules)
