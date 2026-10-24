/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// // import "androguard"

// rule Android_FakeBank_Fanta (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "Jacob Soo Lead Re" (Disabled: vacuous condition without evaluatable strings/modules)
// 		date = "14-July-2016" (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "This rule try to detects Android FakeBank_Fanta" (Disabled: vacuous condition without evaluatable strings/modules)
// 		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.service(/SocketService/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/MyAdmin/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/Receiver/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/NetworkChangeReceiver/i) (Disabled by Oshoosi Hardener)
// 		 (Disabled: vacuous condition without evaluatable strings/modules)
// } (Disabled: vacuous condition without evaluatable strings/modules)
