/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
// import "androguard" (Disabled by Oshoosi Hardener)


rule android_spywaller : android
{
	meta:
		description = "Rule for detection of Android Spywaller samples"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		source = "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking"

	strings:
		$str_1 = "droid.png"
		$str_2 = "getSrvAddr"
		$str_3 = "getSrvPort"		
		$str_4 = "android.intent.action.START_GOOGLE_SERVICE"

	condition:
// 		androguard.certificate.sha1("165F84B05BD33DA1BA0A8E027CEF6026B7005978") or (Identifier fixed/disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.INTERNET/) and (Identifier fixed/disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.READ_PHONE_STATE/) and  (Identifier fixed/disabled by Oshoosi Hardener)
		all of ($str_*)
}
