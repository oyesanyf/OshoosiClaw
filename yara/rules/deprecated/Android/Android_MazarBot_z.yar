/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

// // import "androguard"


rule android_mazarBot_z: android
{
	meta:
	  author = "https://twitter.com/5h1vang"
	  reference_1 = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
	  description = "Yara detection for MazarBOT"
	  sample = "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8"

	strings:
		$str_1 = "android.app.extra.ADD_EXPLANATION"
		$str_2 = "device_policy"
		$str_3 = "content://sms/"
		$str_4 = "#admin_start"
		$str_5 = "kill call"
		$str_6 = "unstop all numbers"
		
	condition:		
// 		androguard.certificate.sha1("50FD99C06C2EE360296DCDA9896AD93CAE32266B") or (Disabled by Oshoosi Hardener)
		
// 		(androguard.package_name("com.mazar") and (Disabled by Oshoosi Hardener)
// 		androguard.activity(/\.DevAdminDisabler/) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/\.DevAdminReceiver/) and  (Disabled by Oshoosi Hardener)
// 		androguard.service(/\.WorkerService/i)) or  (Disabled by Oshoosi Hardener)
		
// 		androguard.permission(/android.permission.INTERNET/) and (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.SEND_SMS/) and (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.CALL_PHONE/) and (Disabled by Oshoosi Hardener)
		all of ($str_*)
}
