/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

// // import "androguard"

// rule batterybotpro : ClickFraud AdFraud SMS Downloader_Trojan android (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html" (Disabled: vacuous condition without evaluatable strings/modules)
// 		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5" (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "https://twitter.com/fdrg21" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android\.permission\.SEND_SMS/) (Disabled by Oshoosi Hardener)
// 		 (Disabled: vacuous condition without evaluatable strings/modules)
// } (Disabled: vacuous condition without evaluatable strings/modules)
