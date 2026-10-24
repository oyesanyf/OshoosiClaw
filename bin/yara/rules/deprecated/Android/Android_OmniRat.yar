/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// import "androguard" (Disabled by Oshoosi Hardener)

// rule Android_OmniRat (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "Jacob Soo Lead Re" (Disabled: vacuous condition without evaluatable strings/modules)
// 		date = "01-July-2016" (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "This rule try to detects OmniRat" (Disabled: vacuous condition without evaluatable strings/modules)
// 		source = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	strings: (Disabled: vacuous condition without evaluatable strings/modules)
// 		$a = "android.engine.apk" (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		(androguard.activity(/com.app.MainActivity/i) and  (Identifier fixed/disabled by Oshoosi Hardener)
// 		 androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/i) and  (Identifier fixed/disabled by Oshoosi Hardener)
// 		 androguard.package_name(/com.app/i)) and $a (Identifier fixed/disabled by Oshoosi Hardener)
// } (Disabled: vacuous condition without evaluatable strings/modules)
