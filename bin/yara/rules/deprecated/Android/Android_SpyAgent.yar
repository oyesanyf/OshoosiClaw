/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// import "androguard" (Disabled by Oshoosi Hardener)


// rule spyAgent (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c" (Disabled: vacuous condition without evaluatable strings/modules)
// 		sample = "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb" (Disabled: vacuous condition without evaluatable strings/modules)
// 		reference = "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/" (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "@koodous_project" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	strings: (Disabled: vacuous condition without evaluatable strings/modules)
// 		$phone = "0597794205" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$caption = "New victim arrived" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc = "http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc_alt = "http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc_alt2= "http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc_alt3= "http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc_alt4 = "http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc_alt5 = "http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc_alt6 = "http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php" (Disabled: vacuous condition without evaluatable strings/modules)
// 		$cc_alt7 = "http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.url(/ksa-sef\.com/) or ($phone and $caption) or ($cc and $cc_alt and $cc_alt2 and $cc_alt3 and $cc_alt4 and $cc_alt5 and $cc_alt6 and $cc_alt7) (Identifier fixed/disabled by Oshoosi Hardener)
// 		 (Disabled: vacuous condition without evaluatable strings/modules)
// } (Disabled: vacuous condition without evaluatable strings/modules)
