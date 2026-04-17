/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// // import "androguard"

rule Android_FakeBank_Fanta
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android FakeBank_Fanta"
		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"

	condition:
// 		androguard.service(/SocketService/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/MyAdmin/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/Receiver/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/NetworkChangeReceiver/i) (Disabled by Oshoosi Hardener)
		
}
